#!/usr/bin/env node
/**
 * Bitbucket Cloud MCP server: READ tools + a fixed, audited set of PR WRITE tools.
 *
 * Capability boundary (by design — verify by reading this file):
 *   - Reads go through bbGet(), hard-coded to GET. It only ever contacts
 *     https://api.bitbucket.org: redirects (the diff/diffstat endpoints 302 to a
 *     repository-level URL) are followed MANUALLY and each hop's origin is
 *     re-checked, so the Authorization header can never be sent off-host — the
 *     allowlist is authoritative, not undici's redirect behavior. Never logs creds.
 *   - Writes go through bbWrite(), which (a) only accepts POST, PUT, or DELETE,
 *     (b) validates the request path — and, for the two PUTs, the request body's
 *     fields and their types — against WRITE_ALLOWLIST, a small, explicit set of
 *     pull-request endpoints, before a request is made (checking the exact path
 *     string and the exact JSON that will be sent), and (c) like bbGet uses
 *     redirect:"manual" and REFUSES to follow any 3xx, so a write can never be
 *     transparently redirected to a different endpoint with creds attached.
 *     The permitted writes are:
 *         POST   .../pullrequests                       create a pull request
 *         PUT    .../pullrequests/{id}                  update a PR — body limited to
 *                                                        title, description, reviewers,
 *                                                        draft, destination branch
 *         POST   .../pullrequests/{id}/comments         comment (general, inline,
 *                                                        multi-line, @-mention, or
 *                                                        reply — all the same POST)
 *         PUT    .../pullrequests/{id}/comments/{cid}   edit a comment — body limited
 *                                                        to its text
 *         POST   .../pullrequests/{id}/comments/{cid}/resolve  resolve a thread
 *         DELETE .../pullrequests/{id}/comments/{cid}/resolve  reopen a thread
 *         POST   .../pullrequests/{id}/approve          approve
 *         DELETE .../pullrequests/{id}/approve          un-approve
 *         POST   .../pullrequests/{id}/request-changes  request changes
 *         DELETE .../pullrequests/{id}/request-changes  withdraw request-changes
 *   - There is deliberately NO path that can merge, decline, delete a PR or a
 *     comment, change a PR's source branch / state / close_source_branch, create or
 *     delete branches, or change repository/workspace settings. Those endpoints
 *     (and body fields) are not in the allowlist, so bbWrite refuses them even if a
 *     future code change or a malicious prompt tries to build the request. The ids
 *     in each allowlisted path are constrained to digits. The workspace/repo
 *     segments can't escape their place in the path:
 *       - a slash, a "%" escape (single- or double-encoded), or any character
 *         outside [A-Za-z0-9._-] is handled at three layers: the `slug` input
 *         schema rejects it; enc() at every call site encodes it, so it can't act
 *         as a separator; and the allowlist's own segment pattern (PATH_SEGMENT)
 *         refuses the result, admitting only those characters or an encoded
 *         {uuid} (%7B…%7D);
 *       - a "." / ".." dot segment is blocked at two: the `slug` input schema, and
 *         isCanonicalPath() in bbWrite, which refuses any path the URL parser would
 *         rewrite (collapsed dot segments, their %2e forms, backslashes) or that
 *         contains an encoded "/", "\", or "." (enc() and PATH_SEGMENT do NOT stop
 *         dot segments: enc("..") is "..", and dots are legal slug characters).
 *     So the path cannot be redirected to a sub-resource like /merge or /decline,
 *     or to another endpoint.
 *   - Inline/multi-line/mention/reply comments all ride on the SAME comments POST,
 *     so they do not widen the write boundary — it stays exactly the ten endpoints
 *     above.
 *   - Emoji reactions on comments are NOT supported: Bitbucket Cloud's public REST
 *     API has no reactions endpoint (only Bitbucket Data Center does).
 *
 * Robustness: every request has a timeout (BITBUCKET_TIMEOUT_MS, default 30s) so a
 * stalled connection can't hang the server; reads (GET) retry with backoff on
 * 429/502/503/504, honoring Retry-After. Writes are NOT auto-retried (a retried
 * POST could double-post a comment or PR), so a 429 on a write surfaces directly.
 * List/comment reads auto-paginate up to a bounded number of pages.
 *
 * Auth: Bitbucket Cloud scoped API token (starts with ATATT). Basic auth =
 *       base64("<email>:<token>"). Scoped tokens do NOT imply one scope from
 *       another, so select each one explicitly. Exact scopes:
 *         read:repository:bitbucket   files, branches, repo info, AND the diff/
 *                                     diffstat 302 redirect target (without it the
 *                                     diff tool 403s even with the PR scope)
 *         read:pullrequest:bitbucket  list/get PRs, comments, PR diff endpoints,
 *                                     and posting, editing, and resolving comments
 *         read:workspace:bitbucket    list_workspace_members (and list repos)
 *         write:pullrequest:bitbucket review actions (approve/request-changes),
 *                                     create PR, and update PR — omit to keep the
 *                                     token from changing PRs themselves
 *       Read + comment set = the three read:* scopes (reads, plus posting, editing,
 *       and resolving comments). Read + write = add write:pullrequest.
 *
 * Required environment variables:
 *   ATLASSIAN_USER_EMAIL   your Atlassian account email
 *   ATLASSIAN_API_TOKEN    a scoped API token (starts with ATATT...)
 * Optional:
 *   BITBUCKET_TIMEOUT_MS   per-request timeout in ms (default 30000)
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { z } from "zod";

const EMAIL = process.env.ATLASSIAN_USER_EMAIL;
const TOKEN = process.env.ATLASSIAN_API_TOKEN;

if (!EMAIL || !TOKEN) {
  process.stderr.write(
    "[bitbucket-mcp] Missing ATLASSIAN_USER_EMAIL and/or ATLASSIAN_API_TOKEN.\n"
  );
  process.exit(1);
}

const API_ORIGIN = "https://api.bitbucket.org";
const BASE = API_ORIGIN + "/2.0";
const AUTH = "Basic " + Buffer.from(`${EMAIL}:${TOKEN}`).toString("base64");
const DEFAULT_LIMIT = 25;
const MAX_LIMIT = 100; // ceiling for a single list call (server auto-paginates to reach it)
const MAX_PAGELEN = 50; // Bitbucket's per-request page size for these list endpoints
const LIST_MAX_PAGES = 5; // bound auto-pagination of list endpoints (safety)
const DIFFSTAT_PAGELEN = 500; // Bitbucket default; max 5000
const MAX_DIFFSTAT_PAGES = 10; // safety cap when following `next` links
const DEFAULT_MAX_DIFF_CHARS = 200_000;
const MAX_FILE_CHARS = 50_000; // cap one get_file result so it stays under the agent's tool-output budget
const DEFAULT_LINE_COUNT = 400; // window size when get_file is given start_line without line_count
const MAX_DIR_DEPTH = 5; // ceiling for list_directory recursion — a bounded shallow tree, never the whole repo
const MAX_REDIRECTS = 5; // diff/diffstat 302 once; this is headroom + a loop guard
const MAX_THREAD_HOPS = 20; // bound the parent walk when pointing a reply at its thread's top-level comment
const PR_STATE_OPEN = "OPEN"; // the only state Bitbucket lets a PR be edited in
const THREAD_ACTION = Object.freeze({ RESOLVE: "resolve", REOPEN: "reopen" });
const TIMEOUT_MS = Number(process.env.BITBUCKET_TIMEOUT_MS) || 30_000;
const MAX_RETRIES = 3; // GET only; writes are never auto-retried
const RETRYABLE_STATUS = new Set([429, 502, 503, 504]);

// Regex source for a bare UUID (no braces), shared by toReviewer, the `slug`
// input schema, and the write allowlist's path segments.
const UUID_SOURCE = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}";

const enc = encodeURIComponent;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const backoffMs = (attempt) => Math.min(500 * 2 ** attempt, 8_000);

/** Error carrying the HTTP status, so callers can react to specific codes (e.g.
 *  review_pull_request treating a 404 on withdraw as "already neutral"). */
class BitbucketError extends Error {
  constructor(status, statusText, where, body) {
    super(`Bitbucket API ${status} ${statusText} for ${where}${body ? ` — ${String(body).slice(0, 300)}` : ""}`);
    this.name = "BitbucketError";
    this.status = status;
    this.body = body ? String(body) : ""; // the response body alone, for matching without the request path
  }
}

/**
 * Single fetch with a hard timeout and (for reads) bounded retry on transient
 * failures. Never follows redirects itself — callers pass redirect:"manual" and
 * handle 3xx — so this can't move a request off-origin. Honors Retry-After on
 * 429. Writes pass { retry:false } so a POST is never silently repeated.
 */
async function doFetch(url, init, { retry = false } = {}) {
  const target = typeof url === "string" ? url : url.href;
  let lastErr;
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    let res;
    try {
      res = await fetch(url, { ...init, signal: AbortSignal.timeout(TIMEOUT_MS) });
    } catch (e) {
      lastErr = e;
      const timedOut = e?.name === "TimeoutError" || e?.name === "AbortError";
      if (retry && attempt < MAX_RETRIES) {
        await sleep(backoffMs(attempt));
        continue;
      }
      throw new Error(
        timedOut
          ? `Request to ${target} timed out after ${TIMEOUT_MS}ms (raise BITBUCKET_TIMEOUT_MS if needed).`
          : `Network error contacting ${target}: ${e?.message || e}`
      );
    }
    if (retry && RETRYABLE_STATUS.has(res.status) && attempt < MAX_RETRIES) {
      const ra = Number(res.headers.get("retry-after"));
      await res.body?.cancel?.().catch(() => {}); // release the discarded error body before retrying
      await sleep(Number.isFinite(ra) && ra >= 0 ? Math.min(ra * 1000, 30_000) : backoffMs(attempt));
      continue;
    }
    return res;
  }
  throw lastErr ?? new Error(`Request to ${target} failed after ${MAX_RETRIES + 1} attempts.`);
}

/**
 * Read primitive. Hard-coded to GET. `pathOrUrl` is either a path beginning with
 * "/" (joined to BASE) or an absolute api.bitbucket.org URL (used to follow the
 * `next` pagination links, which come back fully-qualified). `raw` returns text
 * (file contents / unified diffs); otherwise JSON. Array-valued params are
 * appended once per element so repeatable params (e.g. `path`) work.
 *
 * Redirects are followed MANUALLY so the origin allowlist — not undici's implicit
 * cross-origin header stripping — is what guarantees the Authorization header
 * never leaves api.bitbucket.org. The diff/diffstat endpoints 302 to a
 * same-origin repository URL; a Location pointing off-host is refused here.
 */
async function bbGet(pathOrUrl, { params, raw = false } = {}) {
  let url = new URL(pathOrUrl.startsWith("http") ? pathOrUrl : BASE + pathOrUrl);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v === undefined || v === null || v === "") continue;
      if (Array.isArray(v)) {
        for (const item of v) {
          if (item !== undefined && item !== null && item !== "") url.searchParams.append(k, String(item));
        }
      } else {
        url.searchParams.set(k, String(v));
      }
    }
  }
  for (let hop = 0; ; hop++) {
    if (url.origin !== API_ORIGIN) {
      throw new Error(`Refusing to GET non-Bitbucket origin: ${url.origin}`);
    }
    const res = await doFetch(
      url,
      {
        method: "GET", // never anything else
        headers: { Authorization: AUTH, Accept: raw ? "*/*" : "application/json" },
        redirect: "manual", // we re-validate each hop's origin ourselves (below)
      },
      { retry: true }
    );
    const location = res.status >= 300 && res.status < 400 ? res.headers.get("location") : null;
    if (location) {
      if (hop >= MAX_REDIRECTS) throw new Error(`Too many redirects (>${MAX_REDIRECTS}) starting from ${pathOrUrl}`);
      url = new URL(location, url); // resolve relative Location; origin re-checked next loop
      continue;
    }
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new BitbucketError(res.status, res.statusText, pathOrUrl, body);
    }
    return raw ? res.text() : res.json();
  }
}

/**
 * Auto-paginating GET for list endpoints. Follows Bitbucket's `next` link,
 * accumulating up to `limit` items, bounded by `maxPages`. Returns the collected
 * values plus has_more (true if more exist beyond what was returned, or the page
 * cap was hit). This replaces the old single-page behavior, which silently
 * truncated at one pagelen with no way to page past it.
 */
async function bbGetAll(path, { params = {}, limit = DEFAULT_LIMIT, maxPages = LIST_MAX_PAGES } = {}) {
  const items = [];
  let url = path;
  let p = { ...params, pagelen: Math.min(limit, MAX_PAGELEN) };
  let more = false;
  for (let page = 0; url; page++) {
    if (page >= maxPages) {
      more = true;
      break;
    }
    const data = await bbGet(url, p ? { params: p } : undefined);
    for (const v of data.values || []) {
      if (items.length >= limit) {
        more = true;
        break;
      }
      items.push(v);
    }
    if (items.length >= limit) {
      if (data.next) more = true;
      break;
    }
    url = data.next || null;
    p = undefined; // `next` already carries the query string
  }
  return { values: items, has_more: more };
}

const WRITE_METHODS = new Set(["POST", "PUT", "DELETE"]);
const API_PATH_PREFIX = new URL(BASE).pathname; // "/2.0"

// The PR fields update_pull_request may send, shared by the body allowlist, the
// body builder, and the before/after tripwire so the three can't drift apart.
// Everything else in the PR schema — source, state, close_source_branch,
// merge_commit, … — is refused.
const PR_FIELD = Object.freeze({
  TITLE: "title",
  DESCRIPTION: "description",
  REVIEWERS: "reviewers",
  DRAFT: "draft",
  DESTINATION: "destination",
});
const PR_UPDATE_FIELDS = Object.values(PR_FIELD);
// Watched by the tripwire, but deliberately NOT sendable — this server can't change it.
const CLOSE_SOURCE_BRANCH = "close_source_branch";

// A percent-encoded "/", "\", or "." inside a path segment. No legitimate write
// path contains one (slugs are limited to [A-Za-z0-9._-] or a brace-wrapped UUID,
// ids to digits), and a server that decoded it could route to a path other than
// the one that was checked.
const ENCODED_SEPARATOR = /%(2f|5c|2e)/i;

/**
 * Whether `path` reaches Bitbucket exactly as written. The URL parser collapses
 * "." and ".." segments (including their %2e forms) and turns "\" into "/", so a
 * string like `/repositories/../snippets/pullrequests/1/comments/2` can match an
 * allowlist pattern yet hit a different endpoint. Any path the parser would
 * rewrite — or that hides an encoded separator a server might decode — is refused.
 * @param {unknown} path - Request path relative to /2.0, already percent-encoded.
 * @returns {boolean} true only for a string whose parsed URL keeps the API origin and exactly this path,
 *   with no query, fragment, or encoded "/", "\", or ".".
 */
const isCanonicalPath = (path) => {
  if (typeof path !== "string" || ENCODED_SEPARATOR.test(path)) return false;
  try {
    const url = new URL(BASE + path);
    return url.origin === API_ORIGIN && url.pathname === API_PATH_PREFIX + path && !url.search && !url.hash;
  } catch {
    return false;
  }
};

/**
 * Whether `obj` is a non-empty plain object whose own keys all appear in `allowed`.
 * @param {unknown} obj - The value to check (a request body or a nested piece of one).
 * @param {string[]} allowed - The only keys permitted.
 * @returns {boolean} false for null, arrays, primitives, `{}`, or any key outside `allowed`.
 */
const hasOnlyKeys = (obj, allowed) =>
  obj !== null &&
  typeof obj === "object" &&
  !Array.isArray(obj) &&
  Object.keys(obj).length > 0 &&
  Object.keys(obj).every((k) => allowed.includes(k));

/**
 * Whether `v` is a string.
 * @param {unknown} v - Any value.
 * @returns {boolean} true for a primitive string (including "").
 */
const isString = (v) => typeof v === "string";

// --- Bitbucket's nested request shapes: each builder sits next to the check that
// accepts exactly what it builds, so the two can't drift apart. ---

/**
 * Build a branch reference, as used for a PR's source and destination.
 * @param {string} name - Branch name (may contain slashes).
 * @returns {{ branch: { name: string } }} the reference.
 */
const branchRef = (name) => ({ branch: { name } });

/**
 * Whether `v` is exactly a branch reference as branchRef builds it — never one
 * naming a repository or commit.
 * @param {unknown} v - A candidate `destination` value.
 * @returns {boolean} true only for `{ branch: { name: <non-empty string> } }`.
 */
const isBranchRef = (v) => hasOnlyKeys(v, ["branch"]) && hasOnlyKeys(v.branch, ["name"]) && isString(v.branch.name) && v.branch.name.length > 0;

/**
 * Build a comment's text payload.
 * @param {string} raw - Comment text (Bitbucket Markdown).
 * @returns {{ content: { raw: string } }} the payload.
 */
const commentText = (raw) => ({ content: { raw } });

/**
 * Whether `v` is exactly a comment-text payload as commentText builds it.
 * @param {unknown} v - A candidate request body.
 * @returns {boolean} true only for `{ content: { raw: <string> } }`.
 */
const isCommentText = (v) => hasOnlyKeys(v, ["content"]) && hasOnlyKeys(v.content, ["raw"]) && isString(v.content.raw);

// The two ways a reviewer can be named, as toReviewer builds them.
const REVIEWER_REF_KEYS = ["uuid", "account_id"];

/**
 * Whether `v` is a reviewer reference as toReviewer builds it.
 * @param {unknown} v - One entry of a `reviewers` array.
 * @returns {boolean} true only for `{ uuid: <string> }` or `{ account_id: <string> }`.
 */
const isReviewerRef = (v) => hasOnlyKeys(v, REVIEWER_REF_KEYS) && Object.keys(v).length === 1 && Object.values(v).every(isString);

/**
 * Whether `v` is a list of reviewer references.
 * @param {unknown} v - A candidate `reviewers` value.
 * @returns {boolean} true for an array (possibly empty) whose every entry passes isReviewerRef.
 */
const isReviewerList = (v) => Array.isArray(v) && v.every(isReviewerRef);

/**
 * Whether `v` is a boolean.
 * @param {unknown} v - Any value.
 * @returns {boolean} true only for `true` or `false`.
 */
const isBoolean = (v) => typeof v === "boolean";

// The type each sendable PR field must have, keyed by PR_FIELD.
const PR_FIELD_RULES = Object.freeze({
  [PR_FIELD.TITLE]: isString,
  [PR_FIELD.DESCRIPTION]: isString,
  [PR_FIELD.REVIEWERS]: isReviewerList,
  [PR_FIELD.DRAFT]: isBoolean,
  [PR_FIELD.DESTINATION]: isBranchRef,
});
// Fail at startup — not on the first update — if a sendable field is ever added
// to PR_FIELD without a type rule here.
const fieldWithoutRule = PR_UPDATE_FIELDS.find((f) => typeof PR_FIELD_RULES[f] !== "function");
if (fieldWithoutRule) throw new Error(`[bitbucket-mcp] PR_FIELD_RULES has no type rule for "${fieldWithoutRule}".`);

/**
 * Body rule for `PUT .../pullrequests/{id}`: only PR_UPDATE_FIELDS, each of the
 * type PR_FIELD_RULES gives it — so a `destination` may name nothing but a branch
 * (never a different repository or commit), and `reviewers` only uuid/account_id refs.
 * @param {unknown} body - The parsed JSON body bbWrite is about to send.
 * @returns {boolean} true when the body stays inside the update boundary; false for
 *   a missing/empty body, any other field, or a field of the wrong type.
 */
const isAllowedPullRequestUpdate = (body) =>
  hasOnlyKeys(body, PR_UPDATE_FIELDS) && Object.entries(body).every(([field, value]) => PR_FIELD_RULES[field](value) === true);

/**
 * Body rule for `PUT .../comments/{cid}`: only the comment's text, so an edit
 * can't re-anchor or re-parent a comment.
 * @param {unknown} body - The parsed JSON body bbWrite is about to send.
 * @returns {boolean} true only for exactly `{ content: { raw: <string> } }`.
 */
const isAllowedCommentUpdate = isCommentText;

// One workspace or repo segment as it may appear in a write path: a slug made of
// the characters `slug` allows, or a brace-wrapped UUID as enc() encodes it
// (%7B…%7D). Nothing else — no other "%" escape (so no %2F, no double-encoded
// %252F), no ";", "@", or non-ASCII — can match, so the allowlist enforces the
// same character set as the input schema rather than trusting it.
const PATH_SEGMENT = `(?:[A-Za-z0-9._-]+|%7[Bb]${UUID_SOURCE}%7[Dd])`;

/**
 * Build an anchored allowlist pattern for a path under one repository's
 * pullrequests collection.
 * @param {string} [suffix] - Regex source for what follows `/pullrequests`, e.g. String.raw`/\d+/approve`; "" for the collection itself.
 * @returns {RegExp} `^/repositories/<segment>/<segment>/pullrequests<suffix>$`.
 */
const pullRequestRoute = (suffix = "") => new RegExp(`^/repositories/${PATH_SEGMENT}/${PATH_SEGMENT}/pullrequests${suffix}$`);

/**
 * The set of write endpoints this server may touch. Each entry is a (method,
 * path-pattern) pair, plus — for the PUTs, whose body decides what changes — a
 * `body` rule. bbWrite rejects anything that doesn't match exactly, so
 * merge/decline/delete and arbitrary targets are unreachable. The patterns are
 * anchored; a workspace/repo segment (PATH_SEGMENT) cannot contain a slash or any
 * "%" escape other than an encoded UUID's braces, and the PR and comment ids are
 * constrained to digits. A "." or ".." segment WOULD still match PATH_SEGMENT
 * (dots are legal in slugs), which is why isWriteAllowed also requires isCanonicalPath.
 */
const WRITE_ALLOWLIST = [
  { method: "POST", re: pullRequestRoute(), what: "create pull request" },
  { method: "PUT", re: pullRequestRoute(String.raw`/\d+`), body: isAllowedPullRequestUpdate, what: "update PR title/description/reviewers/draft/destination" },
  { method: "POST", re: pullRequestRoute(String.raw`/\d+/comments`), what: "comment on PR" },
  { method: "PUT", re: pullRequestRoute(String.raw`/\d+/comments/\d+`), body: isAllowedCommentUpdate, what: "edit a PR comment's text" },
  { method: "POST", re: pullRequestRoute(String.raw`/\d+/comments/\d+/resolve`), what: "resolve a comment thread" },
  { method: "DELETE", re: pullRequestRoute(String.raw`/\d+/comments/\d+/resolve`), what: "reopen a comment thread" },
  { method: "POST", re: pullRequestRoute(String.raw`/\d+/approve`), what: "approve PR" },
  { method: "DELETE", re: pullRequestRoute(String.raw`/\d+/approve`), what: "un-approve PR" },
  { method: "POST", re: pullRequestRoute(String.raw`/\d+/request-changes`), what: "request changes on PR" },
  { method: "DELETE", re: pullRequestRoute(String.raw`/\d+/request-changes`), what: "withdraw request-changes on PR" },
];

/**
 * Pure predicate behind the write boundary: the method and path — and, for
 * entries with a body rule, the request body — must all match one allowlist
 * entry, and the path must be a string that survives URL parsing unchanged
 * (isCanonicalPath). Exported so the boundary can be exercised by tests without
 * making any network call.
 * @param {string} method - HTTP method; only POST, PUT, and DELETE can ever pass.
 * @param {string} path - Request path relative to /2.0, already percent-encoded.
 * @param {unknown} [body] - The parsed JSON body to send; checked only by entries with a body rule.
 * @returns {boolean} whether bbWrite may send this request.
 */
export function isWriteAllowed(method, path, body) {
  if (!WRITE_METHODS.has(method) || !isCanonicalPath(path)) return false;
  return WRITE_ALLOWLIST.some((e) => e.method === method && e.re.test(path) && (!e.body || e.body(body)));
}

/**
 * Validate a write and produce exactly what will be sent. The body is serialized
 * FIRST and the parsed result is what gets checked, so a toJSON() or getter can't
 * make the checked object differ from the bytes on the wire; and `path` must be a
 * primitive string, so it can't stringify differently when the URL is built.
 * Exported for tests (pure — no network).
 * @param {string} method - HTTP method.
 * @param {string} path - Request path relative to /2.0.
 * @param {unknown} [body] - The request body; omitted for bodiless writes.
 * @returns {{ url: string, json: string|undefined }} the full URL and the exact JSON text to send.
 * @throws {Error} when the request is outside the write allowlist.
 */
export const prepareWrite = (method, path, body) => {
  const json = body === undefined ? undefined : JSON.stringify(body);
  if (!isWriteAllowed(method, path, json === undefined ? undefined : JSON.parse(json))) {
    const shown = typeof path === "string" ? path : "(a non-string path)"; // never stringify a refused non-string
    throw new Error(
      `bbWrite refuses ${method} ${shown}: not in the write allowlist (or the body has a field it may not send). This server cannot merge, decline, or delete, and a PR update may change only title, description, reviewers, draft, and destination branch.`
    );
  }
  return { url: BASE + path, json };
};

/**
 * The ONLY write primitive. It refuses any method other than POST/PUT/DELETE and
 * any request not in WRITE_ALLOWLIST (path, and body fields for the PUTs) — see
 * prepareWrite. Callers build the request from validated arguments; the allowlist
 * is defense-in-depth so the boundary holds even if a call site is wrong. Like
 * bbGet it uses redirect:"manual" and refuses to follow a 3xx, so a write can
 * never be transparently redirected with creds attached. Writes are never retried.
 * @param {"POST"|"PUT"|"DELETE"} method - HTTP method.
 * @param {string} path - Request path relative to /2.0, built from enc()-encoded segments.
 * @param {{ body?: object }} [options] - `body` is sent as JSON.
 * @returns {Promise<object|string|null>} the parsed JSON response; the raw text if it isn't JSON;
 *   null for a 204 / empty response (DELETE).
 * @throws {Error} when the request is outside the allowlist or Bitbucket answers with a redirect;
 *   {BitbucketError} for any other non-2xx status.
 */
async function bbWrite(method, path, { body } = {}) {
  const { url, json } = prepareWrite(method, path, body);
  const init = { method, headers: { Authorization: AUTH, Accept: "application/json" }, redirect: "manual" };
  if (json !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = json;
  }
  const res = await doFetch(url, init, { retry: false });
  if (res.status >= 300 && res.status < 400) {
    const loc = res.headers.get("location");
    throw new Error(`Refusing to follow a redirect on write ${method} ${path}${loc ? ` → ${loc}` : ""}. Writes must hit the endpoint directly.`);
  }
  if (!res.ok) {
    const t = await res.text().catch(() => "");
    throw new BitbucketError(res.status, res.statusText, path, t);
  }
  if (res.status === 204) return null; // No Content (DELETE)
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

const clampLimit = (n) => {
  const v = Math.trunc(Number(n));
  if (!Number.isFinite(v) || v < 1) return DEFAULT_LIMIT;
  return Math.min(v, MAX_LIMIT);
};

/**
 * Percent-encode a repo-relative file path one segment at a time, preserving the
 * slashes (which the Bitbucket Source API needs literal) while encoding spaces,
 * '#', '?', and non-ASCII. Rejects '..' segments — a path-traversal smell, and
 * never legitimate against the Source API. Exported for tests.
 */
export function encodeRepoPath(path) {
  const segments = String(path)
    .split("/")
    .filter((s) => s.length > 0);
  if (segments.some((s) => s === "..")) throw new Error("path must not contain '..' segments");
  return segments.map(enc).join("/");
}

/**
 * Normalize Bitbucket Source directory entries into the shape list_directory
 * returns. Each raw value becomes `{ path, type }` where type is "directory" for
 * a `commit_directory` and "file" for anything else (`commit_file`) — an unknown
 * type falls back to "file" so the agent can still get_file it. A file's byte
 * `size` is carried through when Bitbucket reports it as a number; directories
 * carry no size. Null/undefined input yields []. Exported for tests (pure — no
 * network).
 */
export function mapDirEntries(values) {
  return (values ?? []).map((v) => {
    const type = v?.type === "commit_directory" ? "directory" : "file";
    const entry = { path: v?.path, type };
    if (type === "file" && typeof v?.size === "number") entry.size = v.size;
    return entry;
  });
}

/**
 * Bound a file's text for a single `get_file` read so it never exceeds the agent's
 * tool-output budget (an over-large result gets silently truncated by the client,
 * which the model reads as "file too large" and skips). When `startLine` (1-based)
 * or `lineCount` is given, return just that window; otherwise return the whole file.
 * Either way the result is hard-capped at MAX_FILE_CHARS, cut at a line boundary,
 * and — whenever anything was withheld — a trailing note states the shown range,
 * the total line count, and how to page (start_line + line_count). A small file
 * read in full is returned verbatim with no note. Exported for tests.
 */
export function sliceFile(text, startLine, lineCount) {
  const lines = String(text).split("\n");
  const total = lines.length;
  const ranged = startLine !== undefined || lineCount !== undefined;
  const from = Math.max(1, startLine ?? 1);
  if (from > total) {
    return `[bitbucket-mcp] start_line ${from} is past the end of the file (${total} line${total === 1 ? "" : "s"}).`;
  }
  const count = lineCount ?? (ranged ? DEFAULT_LINE_COUNT : total);
  const start0 = from - 1;
  let body = lines.slice(start0, start0 + count).join("\n");
  let truncated = false;
  if (body.length > MAX_FILE_CHARS) {
    body = body.slice(0, MAX_FILE_CHARS);
    const lastNl = body.lastIndexOf("\n");
    if (lastNl > 0) body = body.slice(0, lastNl); // don't cut mid-line
    truncated = true;
  }
  const to = start0 + body.split("\n").length;
  if (!ranged && !truncated && to >= total) return body; // whole small file — verbatim
  const note =
    `\n\n[bitbucket-mcp] Showing lines ${from}-${to} of ${total}.` +
    (truncated ? " Output was capped to fit the read budget." : "") +
    " Pass start_line and line_count to read another range.";
  return body + note;
}

/**
 * Build the `inline` object for a PR comment from friendly inputs. Bitbucket's
 * model: `from` anchors to the OLD/removed side, `to` to the NEW/added side; for
 * a multi-line range the start line goes in `start_from`/`start_to` and the end
 * line in `from`/`to`. We expose it as line + optional start_line + line_side.
 *   - single line on new side:  { path, to: line }
 *   - single line on old side:  { path, from: line }
 *   - range on new side:        { path, start_to: start_line, to: line }
 *   - range on old side:        { path, start_from: start_line, from: line }
 *   - file-level (no line):     { path }
 * Exported for tests.
 */
export function buildInline({ file_path, line, start_line, line_side = "new" }) {
  if (!file_path) throw new Error("file_path is required for an inline comment");
  if (line_side !== "new" && line_side !== "old") throw new Error("line_side must be 'new' or 'old'");
  const inline = { path: file_path };
  if (line === undefined) {
    if (start_line !== undefined) throw new Error("start_line requires 'line' (the last line of the range)");
    return inline; // file-level inline comment, not anchored to a specific line
  }
  if (!Number.isInteger(line) || line < 1) throw new Error("line must be a positive integer");
  let start;
  if (start_line !== undefined) {
    if (!Number.isInteger(start_line) || start_line < 1) throw new Error("start_line must be a positive integer");
    if (start_line > line) throw new Error("start_line must be <= line (start_line is the first line of the range, line the last)");
    if (start_line !== line) start = start_line; // equal → treat as single line
  }
  if (line_side === "old") {
    inline.from = line;
    if (start !== undefined) inline.start_from = start;
  } else {
    inline.to = line;
    if (start !== undefined) inline.start_to = start;
  }
  return inline;
}

/**
 * Walk a reply's parent chain up to its thread's top-level comment, so a resolve
 * aimed at a reply can name the comment Bitbucket will actually accept.
 * @param {string} commentsPath - `/repositories/{ws}/{repo}/pullrequests/{id}/comments`, already encoded.
 * @param {object} comment - A comment as Bitbucket returns it (`parent` is set on replies).
 * @returns {Promise<number|null>} the top-level comment's id, or null if the chain is longer than MAX_THREAD_HOPS.
 */
const findThreadRootId = async (commentsPath, comment) => {
  let c = comment;
  for (let hop = 0; c.parent?.id !== undefined; hop++) {
    if (hop >= MAX_THREAD_HOPS) return null;
    c = await bbGet(`${commentsPath}/${c.parent.id}`);
  }
  return c.id;
};

/** Resolve a branch name to its head commit hash (so paths with slashes in the
 *  branch name don't break the Source API). Returns null if it can't resolve. */
async function resolveBranchHash(workspace, repo, branch) {
  try {
    const b = await bbGet(`/repositories/${enc(workspace)}/${enc(repo)}/refs/branches/${enc(branch)}`);
    return b?.target?.hash || null;
  } catch {
    return null;
  }
}

// Candidate PR-template locations, in priority order. Only the first is honored
// natively by Bitbucket Cloud; the rest are GitHub-style conventions some teams
// keep and that tooling can still read.
const TEMPLATE_PATHS = [
  ".bitbucket/pull_request_template.md", // native to Bitbucket Cloud (source branch)
  ".bitbucket/PULL_REQUEST_TEMPLATE.md",
  ".github/pull_request_template.md",
  ".github/PULL_REQUEST_TEMPLATE.md",
  "PULL_REQUEST_TEMPLATE.md",
  "pull_request_template.md",
  "docs/pull_request_template.md",
  "docs/PULL_REQUEST_TEMPLATE.md",
];

/** Look for a PR template at `ref` (ideally a commit hash). Returns
 *  { path, content } for the first match, or null. */
async function findPullRequestTemplate(workspace, repo, ref) {
  for (const tpath of TEMPLATE_PATHS) {
    try {
      const text = await bbGet(`/repositories/${enc(workspace)}/${enc(repo)}/src/${enc(ref)}/${encodeRepoPath(tpath)}`, { raw: true });
      if (text != null && String(text).length > 0) return { path: tpath, content: text };
    } catch {
      // 404 / not present → try the next candidate
    }
  }
  return null;
}

/** Map a reviewer string to Bitbucket's reviewer object. A bare UUID (optionally
 *  brace-wrapped) becomes { uuid }; an account_id becomes { account_id }. Rejects
 *  values that obviously aren't an identifier (an email or a display name with a
 *  space) so the common mistake fails fast with a clear message instead of an
 *  opaque create-PR error. Exported for tests. */
export function toReviewer(s) {
  const v = String(s).trim();
  const m = v.match(new RegExp(`^\\{?(${UUID_SOURCE})\\}?$`));
  if (m) return { uuid: `{${m[1]}}` };
  if (v === "" || /\s/.test(v) || v.includes("@")) {
    throw new Error(
      `"${s}" doesn't look like a Bitbucket account_id or UUID (it has a space or '@'). Reviewers must be an account_id (e.g. "557058:...") or a UUID — not a name or email. Use list_workspace_members to look up a user's account_id.`
    );
  }
  return { account_id: v };
}

/**
 * Whether a Bitbucket user is the person a reviewer reference names.
 * @param {{ uuid?: string, account_id?: string }} user - A user as Bitbucket returns it (e.g. an entry of a PR's `reviewers`).
 * @param {{ uuid?: string, account_id?: string }} ref - A `{ uuid }` or `{ account_id }` from toReviewer.
 * @returns {boolean} true when the uuid (case-insensitively) or the account_id matches; false when `ref` carries neither.
 */
const isSameUser = (user, ref) =>
  (ref.uuid !== undefined && user?.uuid?.toLowerCase() === ref.uuid.toLowerCase()) ||
  (ref.account_id !== undefined && user?.account_id === ref.account_id);

/**
 * Build the PUT body for update_pull_request from the PR as it is now plus the
 * requested changes. Guards against Bitbucket's under-documented PUT semantics:
 * the title, the description, and the reviewer list (with any additions/removals
 * applied) are ALWAYS sent — the current values when unchanged — so editing one
 * field can never silently wipe another. `draft` and `destination` are sent only
 * when requested. Exported for tests (pure — no network).
 * @param {object} current - The PR as returned by `GET .../pullrequests/{id}`.
 * @param {object} changes - The requested edits; omit a field to leave it alone.
 * @param {string} [changes.title] - New title.
 * @param {string} [changes.description] - New description (Bitbucket Markdown); "" clears it.
 * @param {string[]} [changes.add_reviewers] - account_ids/UUIDs to add; people already reviewing are skipped.
 * @param {string[]} [changes.remove_reviewers] - account_ids/UUIDs to remove; each must currently be a reviewer.
 * @param {boolean} [changes.draft] - true converts to draft; false marks it ready for review.
 * @param {string} [changes.destination_branch] - Branch to retarget the PR to.
 * @returns {{ body: object, updated: string[] }} the request body, and the PR_FIELD names the caller asked to change.
 * @throws {Error} when nothing was requested, a reviewer id is malformed (see toReviewer), someone in
 *   remove_reviewers isn't a current reviewer, or the same person is both added and removed (by either id form).
 */
export const buildPullRequestUpdate = (
  current,
  { title, description, add_reviewers = [], remove_reviewers = [], draft, destination_branch }
) => {
  const updated = [];
  const body = { [PR_FIELD.TITLE]: title ?? current.title };
  if (title !== undefined) updated.push(PR_FIELD.TITLE);
  const nextDescription = description ?? current.summary?.raw ?? current.description;
  if (typeof nextDescription === "string") body[PR_FIELD.DESCRIPTION] = nextDescription;
  if (description !== undefined) updated.push(PR_FIELD.DESCRIPTION);

  const adds = add_reviewers.map(toReviewer);
  const removes = remove_reviewers.map(toReviewer);
  const currentReviewers = current.reviewers ?? [];
  const notReviewing = removes.find((r) => !currentReviewers.some((u) => isSameUser(u, r)));
  if (notReviewing) {
    const names = currentReviewers.map((u) => `${u.display_name} (${u.account_id ?? u.uuid})`).join(", ") || "none";
    throw new Error(`${notReviewing.account_id ?? notReviewing.uuid} is not a reviewer on this PR, so it can't be removed. Current reviewers: ${names}.`);
  }
  // Resolve removals to the full current users, which carry both uuid and
  // account_id, so someone added by one id form and removed by the other is caught.
  const removedUsers = currentReviewers.filter((u) => removes.some((r) => isSameUser(u, r)));
  const both = adds.find((a) => removedUsers.some((u) => isSameUser(u, a)));
  if (both) throw new Error(`${both.account_id ?? both.uuid} is in both add_reviewers and remove_reviewers.`);
  const kept = currentReviewers
    .filter((u) => !removedUsers.includes(u))
    .map((u) => (u.uuid ? { uuid: u.uuid } : u.account_id ? { account_id: u.account_id } : null))
    .filter(Boolean);
  // Skip anyone already reviewing (matched on the full user) and duplicates
  // within add_reviewers itself.
  const added = adds.filter((a, i) => !currentReviewers.some((u) => isSameUser(u, a)) && adds.findIndex((b) => isSameUser(b, a)) === i);
  body[PR_FIELD.REVIEWERS] = [...kept, ...added];
  if (adds.length || removes.length) updated.push(PR_FIELD.REVIEWERS);

  if (draft !== undefined) {
    body[PR_FIELD.DRAFT] = draft;
    updated.push(PR_FIELD.DRAFT);
  }
  if (destination_branch !== undefined) {
    body[PR_FIELD.DESTINATION] = branchRef(destination_branch);
    updated.push(PR_FIELD.DESTINATION);
  }
  if (!updated.length) {
    throw new Error("Nothing to update: pass at least one of title, description, add_reviewers, remove_reviewers, draft, destination_branch.");
  }
  return { body, updated };
};

/**
 * How to read each PR field the update tripwire watches. Each reader takes a PR
 * as Bitbucket returns it and returns a JSON-comparable value (reviewers as a
 * sorted list of account_ids, so order doesn't count as a change).
 * @type {Record<string, (pr: object) => unknown>}
 */
const WATCHED_PR_FIELDS = {
  [PR_FIELD.TITLE]: (pr) => pr?.title,
  [PR_FIELD.DESCRIPTION]: (pr) => pr?.summary?.raw ?? pr?.description ?? "",
  [PR_FIELD.REVIEWERS]: (pr) => (pr?.reviewers ?? []).map((u) => u.account_id ?? u.uuid).sort(),
  [PR_FIELD.DRAFT]: (pr) => Boolean(pr?.draft),
  [PR_FIELD.DESTINATION]: (pr) => pr?.destination?.branch?.name,
  [CLOSE_SOURCE_BRANCH]: (pr) => Boolean(pr?.close_source_branch),
};

/**
 * List PR fields that differ between `before` and `after` although the caller
 * didn't ask to change them — a tripwire for Bitbucket's under-documented PUT
 * semantics (e.g. a partial update resetting a field it left out). Each entry
 * says how it can be restored: fields update_pull_request can send are restorable
 * with another call; close_source_branch only in the Bitbucket UI. Exported for
 * tests (pure — no network).
 * @param {object} before - The PR as read just before the update.
 * @param {object} after - The PR Bitbucket returned from the update.
 * @param {string[]} updated - The fields the caller asked to change (from buildPullRequestUpdate).
 * @returns {Array<{ field: string, before: unknown, after: unknown, restore: string }>} one entry per
 *   unexpected change; empty when only the requested fields moved.
 */
export const findUnexpectedChanges = (before, after, updated) =>
  Object.entries(WATCHED_PR_FIELDS)
    .filter(([field]) => !updated.includes(field))
    .map(([field, read]) => ({ field, before: read(before), after: read(after) }))
    .filter((c) => JSON.stringify(c.before) !== JSON.stringify(c.after))
    .map((c) => ({
      ...c,
      restore: PR_UPDATE_FIELDS.includes(c.field)
        ? "with update_pull_request, using the 'before' value"
        : "only in the Bitbucket UI — this server can't change it",
    }));

/**
 * Drop items whose `id` was already seen, keeping each one's first occurrence in
 * order. A paginated listing can repeat an item when a page boundary shifts while
 * new items are added. Exported for tests (pure — no network).
 * @param {Array<{ id: unknown }>} items - e.g. raw comments from bbGetAll.
 * @returns {Array<{ id: unknown }>} the items with unique ids, in first-seen order. Items are not copied.
 */
export const uniqueById = (items) => {
  const seen = new Set();
  return items.filter((item) => {
    if (seen.has(item.id)) return false;
    seen.add(item.id);
    return true;
  });
};

/**
 * Group flat comment summaries (from commentSummary) into threads: each root gets
 * a nested `replies` array, in the order the comments were given. A reply whose
 * parent wasn't in the fetched set (e.g. cut off by `limit`) becomes a root marked
 * `parent_not_fetched: true` rather than being dropped. A comment id that appears
 * more than once (e.g. a page boundary shifting while new comments arrive) is kept
 * once, at its first position. Empty `replies` arrays are omitted to keep the
 * output compact. Exported for tests (pure — no network).
 * @param {Array<{ id: number, parent_id?: number }>} comments - Comment summaries, oldest first.
 * @returns {Array<object>} the thread roots, each a comment summary with optional nested `replies`.
 */
export const buildCommentThreads = (comments) => {
  const nodes = new Map(uniqueById(comments).map((c) => [c.id, { ...c, replies: [] }]));
  const roots = [];
  for (const node of nodes.values()) {
    const parent = node.parent_id !== undefined ? nodes.get(node.parent_id) : undefined;
    if (parent && parent !== node) {
      parent.replies.push(node);
    } else {
      if (node.parent_id !== undefined) node.parent_not_fetched = true;
      roots.push(node);
    }
  }
  /**
   * Drop empty `replies` arrays, depth-first, so leaf comments stay compact.
   * @param {object} node - A thread node; mutated in place.
   * @returns {void}
   */
  const prune = (node) => {
    if (node.replies.length) node.replies.forEach(prune);
    else delete node.replies;
  };
  roots.forEach(prune);
  return roots;
};

// --- compactors: trim Bitbucket's verbose JSON to the useful fields ---
const prSummary = (pr) => ({
  id: pr.id,
  title: pr.title,
  state: pr.state,
  draft: pr.draft,
  author: pr.author?.display_name,
  source: pr.source?.branch?.name,
  destination: pr.destination?.branch?.name,
  created_on: pr.created_on,
  updated_on: pr.updated_on,
  url: pr.links?.html?.href,
});

const repoSummary = (r) => ({
  full_name: r.full_name,
  is_private: r.is_private,
  description: r.description,
  mainbranch: r.mainbranch?.name,
  language: r.language,
  updated_on: r.updated_on,
  url: r.links?.html?.href,
});

const branchSummary = (b) => ({
  name: b.name,
  target_hash: b.target?.hash,
  target_date: b.target?.date,
});

/**
 * Compact a PR comment to the fields an agent reads, replies to, edits, or resolves by.
 * @param {object} c - A comment as Bitbucket returns it.
 * @returns {object} id, author, timestamps, `parent_id` (replies only), `deleted`,
 *   `resolved`/`resolved_by` (resolved threads only), the inline anchor (if any), and the raw text.
 *   Fields Bitbucket omits come back undefined and drop out of the JSON.
 */
const commentSummary = (c) => ({
  id: c.id,
  author: c.user?.display_name,
  created_on: c.created_on,
  updated_on: c.updated_on,
  parent_id: c.parent?.id, // present on replies — shows thread structure
  deleted: c.deleted || undefined,
  resolved: c.resolution ? true : undefined,
  resolved_by: c.resolution?.user?.display_name,
  inline: c.inline ? { path: c.inline.path, from: c.inline.from, to: c.inline.to, start_from: c.inline.start_from, start_to: c.inline.start_to } : undefined,
  content: c.content?.raw,
});

const participantSummary = (p) => ({
  user: p?.user?.display_name,
  role: p?.role,
  approved: p?.approved,
  state: p?.state,
  participated_on: p?.participated_on,
});

/**
 * Compact a PR reviewer to what an agent needs to name them and to pass them to
 * update_pull_request's add/remove_reviewers (either id works there; uuid covers
 * a user Bitbucket returns without an account_id).
 * @param {object} [u] - A user object from a PR's `reviewers`.
 * @returns {{ display_name?: string, account_id?: string, uuid?: string }} fields are undefined when Bitbucket omits them.
 */
const reviewerSummary = (u) => ({ display_name: u?.display_name, account_id: u?.account_id, uuid: u?.uuid });

const userSummary = (u) => ({
  account_id: u?.account_id,
  uuid: u?.uuid,
  nickname: u?.nickname,
  display_name: u?.display_name,
  // Ready to paste into a comment's content to @-mention this person.
  mention: u?.account_id ? `@{${u.account_id}}` : undefined,
});

// MCP tool annotations: hints a client may use to decide how to present or
// confirm a call. Every read tool shares this; each write tool states its own.
const READ_ONLY_TOOL = Object.freeze({ readOnlyHint: true, openWorldHint: true });

const ok = (data) => ({ content: [{ type: "text", text: JSON.stringify(data, null, 2) }] });
const okText = (text) => ({ content: [{ type: "text", text }] });
const fail = (msg) => ({ content: [{ type: "text", text: msg }], isError: true });
const wrap = (fn) => async (args) => {
  try {
    return await fn(args);
  } catch (e) {
    return fail(`[bitbucket-mcp] ${e?.message || String(e)}`);
  }
};

// Workspace and repo identifiers, limited to what Bitbucket actually issues:
// slugs of letters, digits, '.', '_', '-' (never just "." or "..", which the URL
// parser would collapse — e.g. workspace ".." turns a comment PUT into a snippet
// endpoint), or a brace-wrapped UUID. So no slash, backslash, '%', or other
// character that could change which endpoint a path reaches. This makes the
// invariant the write allowlist relies on explicit at the input boundary, instead
// of leaving it to enc() + the allowlist alone. Do NOT apply this to
// ref/branch/path, which may contain slashes and rely on enc() to encode them.
const SLUG_PATTERN = new RegExp(`^(?:\\{${UUID_SOURCE}\\}|(?!\\.\\.?$)[A-Za-z0-9._-]+)$`);
export const slug = z.string().regex(SLUG_PATTERN, "must be a Bitbucket slug (letters, digits, '.', '_', '-'; not '.' or '..') or a {uuid}");

export const server = new McpServer({ name: "Bitbucket", version: "2.2.1" });

// ============================ READ TOOLS ============================

server.registerTool(
  "list_pull_requests",
  {
    title: "List pull requests",
    description: "List pull requests for a Bitbucket repository. Defaults to OPEN PRs.",
    inputSchema: {
      workspace: slug.describe("Workspace slug, e.g. 'acme'"),
      repo: slug.describe("Repository slug, e.g. 'frontend-app'"),
      state: z.enum(["OPEN", "MERGED", "DECLINED", "SUPERSEDED"]).optional().describe("PR state filter (default OPEN)"),
      limit: z.number().int().optional().describe(`Max results (1-${MAX_LIMIT}, default ${DEFAULT_LIMIT}); the server auto-paginates to reach it`),
    },
    annotations: READ_ONLY_TOOL,
  },
  wrap(async ({ workspace, repo, state, limit }) => {
    const { values, has_more } = await bbGetAll(`/repositories/${enc(workspace)}/${enc(repo)}/pullrequests`, {
      params: { state: state || "OPEN" },
      limit: clampLimit(limit),
    });
    return ok({ count: values.length, has_more, pull_requests: values.map(prSummary) });
  })
);

server.registerTool(
  "get_pull_request",
  {
    title: "Get pull request",
    description:
      "Fetch details for a single pull request, including description, reviewers (each with account_id and uuid — either can be passed to update_pull_request's remove_reviewers), and per-reviewer approval state.",
    inputSchema: {
      workspace: slug,
      repo: slug,
      pull_request_id: z.number().int().describe("Numeric PR id"),
    },
    annotations: READ_ONLY_TOOL,
  },
  wrap(async ({ workspace, repo, pull_request_id }) => {
    const pr = await bbGet(`/repositories/${enc(workspace)}/${enc(repo)}/pullrequests/${pull_request_id}`);
    return ok({
      ...prSummary(pr),
      description: pr.summary?.raw ?? pr.description,
      reviewers: (pr.reviewers || []).map(reviewerSummary),
      participants: (pr.participants || []).map((p) => ({ name: p.user?.display_name, role: p.role, approved: p.approved, state: p.state })),
    });
  })
);

server.registerTool(
  "get_pull_request_comments",
  {
    title: "Get pull request comments",
    description:
      "List comments on a pull request (general and inline). Each comment includes its 'id' (use it as 'parent_id' on create_pull_request_comment to reply, or as 'comment_id' to edit or resolve) and, for replies, 'parent_id'. " +
      "Set 'threaded' true to get them grouped into threads instead: each top-level comment with its replies nested under 'replies' — the top-level comment's id is the one resolve_pull_request_comment takes. " +
      "'resolved' marks a resolved thread.",
    inputSchema: {
      workspace: slug,
      repo: slug,
      pull_request_id: z.number().int(),
      limit: z.number().int().optional().describe(`Max comments to fetch (1-${MAX_LIMIT}, default ${DEFAULT_LIMIT}); the server auto-paginates to reach it`),
      threaded: z.boolean().optional().describe("Group comments into threads (replies nested under their top-level comment). Default false: a flat list."),
    },
    annotations: READ_ONLY_TOOL,
  },
  wrap(async ({ workspace, repo, pull_request_id, limit, threaded }) => {
    const { values, has_more } = await bbGetAll(`/repositories/${enc(workspace)}/${enc(repo)}/pullrequests/${pull_request_id}/comments`, {
      limit: clampLimit(limit),
    });
    // Dedupe once, before counting, so `count` and both views agree.
    const comments = uniqueById(values).map(commentSummary);
    if (!threaded) return ok({ count: comments.length, has_more, comments });
    const threads = buildCommentThreads(comments);
    return ok({
      count: comments.length,
      thread_count: threads.length,
      has_more,
      ...(has_more ? { note: `Only the first ${comments.length} comments were fetched, so some threads may be missing replies. Raise 'limit' (max ${MAX_LIMIT}) to see more.` } : {}),
      threads,
    });
  })
);

server.registerTool(
  "get_pull_request_diff",
  {
    title: "Get pull request diff",
    description:
      "Comprehensive diff for reviewing a pull request. Returns a per-file summary (status + lines added/removed, from diffstat) and, by default, the raw unified diff text. Scope to specific files with 'path', tune surrounding lines with 'context', and use 'ignore_whitespace' to hide whitespace-only changes. Large diffs are truncated (with a note) — narrow with 'path' or set 'include_diff' false for just the summary.",
    inputSchema: {
      workspace: slug,
      repo: slug,
      pull_request_id: z.number().int(),
      path: z.union([z.string(), z.array(z.string())]).optional().describe("Limit the diff to one file/path or a list of them"),
      context: z.number().int().optional().describe("Lines of context around each change (Bitbucket default is 3)"),
      ignore_whitespace: z.boolean().optional().describe("Ignore whitespace-only changes"),
      include_diff: z.boolean().optional().describe("Include the raw unified diff text (default true). Set false for only the per-file summary."),
      max_diff_chars: z.number().int().optional().describe(`Truncate the raw diff beyond this many characters (default ${DEFAULT_MAX_DIFF_CHARS})`),
    },
    annotations: READ_ONLY_TOOL,
  },
  wrap(async ({ workspace, repo, pull_request_id, path, context, ignore_whitespace, include_diff, max_diff_chars }) => {
    const ws = enc(workspace);
    const rp = enc(repo);
    const out = { pull_request_id };

    // Light PR context (best-effort — never fail the diff over this).
    try {
      const pr = await bbGet(`/repositories/${ws}/${rp}/pullrequests/${pull_request_id}`);
      out.title = pr.title;
      out.state = pr.state;
      out.source = pr.source?.branch?.name;
      out.destination = pr.destination?.branch?.name;
    } catch {
      /* ignore */
    }

    // Per-file summary from diffstat (paginated; follow `next`, bounded).
    const files = [];
    let totalAdded = 0;
    let totalRemoved = 0;
    let dsUrl = `/repositories/${ws}/${rp}/pullrequests/${pull_request_id}/diffstat`;
    let dsParams = { pagelen: DIFFSTAT_PAGELEN, path, ignore_whitespace: ignore_whitespace ? true : undefined };
    let truncatedFiles = false;
    for (let page = 0; dsUrl; page++) {
      if (page >= MAX_DIFFSTAT_PAGES) {
        truncatedFiles = true;
        break;
      }
      const data = await bbGet(dsUrl, dsParams ? { params: dsParams } : undefined);
      for (const d of data.values || []) {
        const added = d.lines_added ?? 0;
        const removed = d.lines_removed ?? 0;
        totalAdded += added;
        totalRemoved += removed;
        files.push({
          path: d.new?.path || d.old?.path,
          status: d.status,
          lines_added: added,
          lines_removed: removed,
          ...(d.status === "renamed" && d.old?.path ? { old_path: d.old.path } : {}),
        });
      }
      dsUrl = data.next || null;
      dsParams = undefined; // `next` already carries the query string
    }
    out.summary = { files_changed: files.length, lines_added: totalAdded, lines_removed: totalRemoved };
    if (truncatedFiles) {
      out.summary.truncated = true;
      out.summary.note = `Counts are a LOWER BOUND: stopped after ${MAX_DIFFSTAT_PAGES} diffstat pages and more files exist. Narrow with 'path'.`;
    }
    out.files = files;

    // Raw unified diff (best-effort: a 555 means Bitbucket couldn't generate it).
    if (include_diff !== false) {
      try {
        let text = await bbGet(`/repositories/${ws}/${rp}/pullrequests/${pull_request_id}/diff`, {
          params: { path, context, ignore_whitespace: ignore_whitespace ? true : undefined },
          raw: true,
        });
        const cap = max_diff_chars && max_diff_chars > 0 ? max_diff_chars : DEFAULT_MAX_DIFF_CHARS;
        if (text.length > cap) {
          // Trim back to the last newline so the returned diff ends on a complete
          // line (no split surrogate pair, no misleading half-hunk).
          let cut = text.slice(0, cap);
          const nl = cut.lastIndexOf("\n");
          if (nl > 0) cut = cut.slice(0, nl);
          out.diff_truncated = `Diff was ${text.length} chars; truncated to ${cut.length} (trimmed to a line boundary). Narrow with 'path' or raise 'max_diff_chars'.`;
          text = cut;
        }
        out.diff = text;
      } catch (e) {
        out.diff_omitted = `Could not fetch the raw diff (${e?.message || e}). The per-file summary above is still accurate; try scoping with 'path'.`;
      }
    }

    return ok(out);
  })
);

server.registerTool(
  "get_pull_request_template",
  {
    title: "Get pull request template",
    description:
      "Find and return a repository's pull request template, if one exists. Checks the Bitbucket-native location (.bitbucket/pull_request_template.md) first, then common GitHub-style fallbacks. Looks on the given branch (resolved to its head commit) or the repo's main branch. Use this before create_pull_request to draft a description that follows the team's template.",
    inputSchema: {
      workspace: slug,
      repo: slug,
      branch: z.string().optional().describe("Branch to read the template from (defaults to the repo's main branch). Use the PR's source branch to match what Bitbucket would apply."),
    },
    annotations: READ_ONLY_TOOL,
  },
  wrap(async ({ workspace, repo, branch }) => {
    let ref = branch;
    if (!ref) {
      const info = await bbGet(`/repositories/${enc(workspace)}/${enc(repo)}`);
      ref = info.mainbranch?.name;
      if (!ref) return fail("Could not determine the repository's main branch; pass 'branch' explicitly.");
    }
    // Prefer the head commit hash: the Source API can't read a {ref} that
    // contains a slash, so a slashed branch name only works once resolved.
    const hash = await resolveBranchHash(workspace, repo, ref);
    if (!hash && ref.includes("/")) {
      return ok({
        found: false,
        branch: ref,
        note: "Could not resolve the branch's head commit, and a branch name containing '/' can't be read directly via the Source API. Pass a commit hash, or a slashless branch, as 'branch'.",
      });
    }
    const tpl = await findPullRequestTemplate(workspace, repo, hash || ref);
    if (!tpl) {
      return ok({ found: false, checked_paths: TEMPLATE_PATHS, branch: ref, note: "No PR template found at any known location on this branch." });
    }
    return ok({ found: true, path: tpl.path, branch: ref, native: tpl.path === TEMPLATE_PATHS[0], content: tpl.content });
  })
);

server.registerTool(
  "list_repositories",
  {
    title: "List repositories",
    description: "List repositories in a workspace, optionally filtered by a name substring.",
    inputSchema: {
      workspace: slug,
      query: z.string().optional().describe("Case-insensitive substring to match in the repo name"),
      limit: z.number().int().optional().describe(`Max results (1-${MAX_LIMIT}, default ${DEFAULT_LIMIT}); the server auto-paginates to reach it`),
    },
    annotations: READ_ONLY_TOOL,
  },
  wrap(async ({ workspace, query, limit }) => {
    const params = { sort: "-updated_on" };
    if (query) params.q = `name ~ "${query.replace(/"/g, '\\"')}"`;
    const { values, has_more } = await bbGetAll(`/repositories/${enc(workspace)}`, { params, limit: clampLimit(limit) });
    return ok({ count: values.length, has_more, repositories: values.map(repoSummary) });
  })
);

server.registerTool(
  "list_branches",
  {
    title: "List branches",
    description: "List branches in a repository, optionally filtered by name substring.",
    inputSchema: {
      workspace: slug,
      repo: slug,
      query: z.string().optional().describe("Case-insensitive substring to match in the branch name"),
      limit: z.number().int().optional().describe(`Max results (1-${MAX_LIMIT}, default ${DEFAULT_LIMIT}); the server auto-paginates to reach it`),
    },
    annotations: READ_ONLY_TOOL,
  },
  wrap(async ({ workspace, repo, query, limit }) => {
    const params = {};
    if (query) params.q = `name ~ "${query.replace(/"/g, '\\"')}"`;
    const { values, has_more } = await bbGetAll(`/repositories/${enc(workspace)}/${enc(repo)}/refs/branches`, { params, limit: clampLimit(limit) });
    return ok({ count: values.length, has_more, branches: values.map(branchSummary) });
  })
);

server.registerTool(
  "list_workspace_members",
  {
    title: "List workspace members",
    description:
      "List members of a Bitbucket workspace so you can @-mention them in comments or add them as reviewers. Returns each member's account_id, uuid, nickname, display_name, and a ready-to-use 'mention' string ('@{account_id}'). Filter by name with 'query'. To tag someone, copy their 'mention' value into a comment's 'content'. To add a reviewer, pass their 'account_id' in create_pull_request's 'reviewers' or update_pull_request's 'add_reviewers'. (Requires the token's workspace read scope.)",
    inputSchema: {
      workspace: slug,
      query: z.string().optional().describe("Case-insensitive substring matched against display_name or nickname"),
      limit: z.number().int().optional().describe(`Max results (1-${MAX_LIMIT}, default ${DEFAULT_LIMIT})`),
    },
    annotations: READ_ONLY_TOOL,
  },
  wrap(async ({ workspace, query, limit }) => {
    const want = clampLimit(limit);
    // The members endpoint has no server-side name filter, so when filtering we
    // scan a wider set of pages and narrow client-side.
    const { values, has_more } = await bbGetAll(`/workspaces/${enc(workspace)}/members`, {
      limit: query ? MAX_LIMIT : want,
      maxPages: query ? LIST_MAX_PAGES : Math.max(1, Math.ceil(want / MAX_PAGELEN)),
    });
    let members = values.map((m) => userSummary(m.user || m)).filter((u) => u.account_id || u.display_name);
    let more = has_more;
    if (query) {
      const q = query.toLowerCase();
      members = members.filter((u) => (u.display_name || "").toLowerCase().includes(q) || (u.nickname || "").toLowerCase().includes(q));
      more = members.length > want;
    }
    const limited = members.slice(0, want);
    return ok({ count: limited.length, has_more: more, members: limited });
  })
);

server.registerTool(
  "get_file",
  {
    title: "Get file contents",
    description:
      "Read the contents of a file from a repository. If 'ref' is omitted, the repo's main branch is used. " +
      `Large files are capped at ~${MAX_FILE_CHARS.toLocaleString()} chars; to read past the cap (or to focus on one area), ` +
      "pass 'start_line' (1-based) and 'line_count' — the PR diff already tells you which lines changed. The result " +
      "notes the shown range and total line count when anything is withheld.",
    inputSchema: {
      workspace: slug,
      repo: slug,
      path: z.string().describe("File path within the repo, e.g. 'src/index.ts'"),
      ref: z.string().optional().describe("Branch name, tag, or commit hash (defaults to the main branch)"),
      start_line: z
        .number()
        .int()
        .min(1)
        .optional()
        .describe("1-based first line to return (for large files). Omit to start at the top."),
      line_count: z
        .number()
        .int()
        .min(1)
        .optional()
        .describe(`How many lines to return from start_line (default ${DEFAULT_LINE_COUNT} when start_line is set).`),
    },
    annotations: READ_ONLY_TOOL,
  },
  wrap(async ({ workspace, repo, path, ref, start_line, line_count }) => {
    let commit = ref;
    if (!commit) {
      const repoInfo = await bbGet(`/repositories/${enc(workspace)}/${enc(repo)}`);
      commit = repoInfo.mainbranch?.name;
      if (!commit) return fail("Could not determine the repository's main branch; pass 'ref' explicitly.");
    }
    const cleanPath = encodeRepoPath(path);
    const text = await bbGet(`/repositories/${enc(workspace)}/${enc(repo)}/src/${enc(commit)}/${cleanPath}`, { raw: true });
    return okText(sliceFile(text, start_line, line_count));
  })
);

server.registerTool(
  "list_directory",
  {
    title: "List directory contents",
    description:
      "List the files and subdirectories at a path in a repository, so you can discover REAL file paths instead of guessing them. " +
      "When a get_file read comes back not-found, do NOT keep trying speculative paths — call this on the parent directory (or the repo root, then narrow) to see what actually exists, then get_file the right entry. " +
      "It works for any language or layout, and for targets that are not imports at all (a CSS custom property's stylesheet, a config file, a generated artifact). " +
      "'path' defaults to the repo root; omit it to list the top level. Set 'max_depth' > 1 to recurse a few levels when you need to locate something under a subtree. " +
      "If 'ref' is omitted the repo's main branch is used. Returns each entry's 'path' and 'type' ('file' | 'directory') — names only; use get_file to read a file's contents.",
    inputSchema: {
      workspace: slug,
      repo: slug,
      path: z.string().optional().describe("Directory path within the repo, e.g. 'src/components'. Omit for the repo root."),
      ref: z.string().optional().describe("Branch name, tag, or commit hash (defaults to the main branch)"),
      max_depth: z
        .number()
        .int()
        .min(1)
        .max(MAX_DIR_DEPTH)
        .optional()
        .describe(`Recurse this many levels (1-${MAX_DIR_DEPTH}, default 1 = just this directory).`),
      limit: z
        .number()
        .int()
        .optional()
        .describe(`Max entries (1-${MAX_LIMIT}, default ${DEFAULT_LIMIT}); the server auto-paginates to reach it`),
    },
    annotations: READ_ONLY_TOOL,
  },
  wrap(async ({ workspace, repo, path, ref, max_depth, limit }) => {
    let commit = ref;
    if (!commit) {
      const repoInfo = await bbGet(`/repositories/${enc(workspace)}/${enc(repo)}`);
      commit = repoInfo.mainbranch?.name;
      if (!commit) return fail("Could not determine the repository's main branch; pass 'ref' explicitly.");
    }
    // The Source API lists a directory when the path ends in "/" (the repo root is
    // just the commit + "/"). A trailing slash is the documented, redirect-free way
    // to get a listing; a file path with it 404s (caught by wrap) — use get_file.
    const cleanPath = encodeRepoPath(path ?? "");
    const dirUrl = `/repositories/${enc(workspace)}/${enc(repo)}/src/${enc(commit)}/${cleanPath ? `${cleanPath}/` : ""}`;
    const params = {};
    if (max_depth && max_depth > 1) params.max_depth = Math.min(max_depth, MAX_DIR_DEPTH);
    const { values, has_more } = await bbGetAll(dirUrl, { params, limit: clampLimit(limit) });
    const entries = mapDirEntries(values);
    return ok({ path: path ?? "", ref: commit, count: entries.length, has_more, entries });
  })
);

// ============================ WRITE TOOLS ============================
// Every write below goes through bbWrite(), which enforces WRITE_ALLOWLIST.

server.registerTool(
  "create_pull_request_comment",
  {
    title: "Comment on a pull request",
    description:
      "Post a comment on a pull request. Modes:\n" +
      "• General comment (a 'comment-only review' in GitHub terms): just pass 'content'.\n" +
      "• Inline comment: add 'file_path' and 'line' to anchor it to a diff line. Use 'line_side' to pick the new (added) or old (removed) side.\n" +
      "• Multi-line inline comment: also pass 'start_line' (the first line of the range; 'line' is the last).\n" +
      "• Reply: pass 'parent_id' (a comment id from get_pull_request_comments). A reply inherits the parent's location, so omit file_path/line.\n" +
      "To @-mention/tag a user, include their mention token '@{account_id}' in 'content' (get it from list_workspace_members).",
    inputSchema: {
      workspace: slug,
      repo: slug,
      pull_request_id: z.number().int(),
      content: z.string().describe("Comment text (Bitbucket Markdown). Tag a user with '@{account_id}'."),
      file_path: z.string().optional().describe("File path to anchor an inline comment to, e.g. 'src/index.ts'. Omit for a general comment."),
      line: z.number().int().optional().describe("Line number for the inline comment (the last line, if a range). Requires file_path."),
      start_line: z.number().int().optional().describe("First line of a MULTI-LINE inline comment range (requires file_path and line; must be <= line)."),
      line_side: z.enum(["new", "old"]).optional().describe("Which side of the diff the line(s) refer to: 'new' (added, default) or 'old' (removed)."),
      parent_id: z.number().int().optional().describe("Reply to this existing comment id (from get_pull_request_comments). Replies inherit the parent's anchor — omit file_path/line."),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  },
  /**
   * Post a comment (POST .../comments): general, inline (single or multi-line), or a reply.
   * @param {{ workspace: string, repo: string, pull_request_id: number, content: string, file_path?: string,
   *   line?: number, start_line?: number, line_side?: "new"|"old", parent_id?: number }} args - Validated tool input.
   * @returns {Promise<object>} the tool result: the new comment's id, parent/inline anchor, and URL; an isError result
   *   for a reply that also passes an anchor, or a line without a file. buildInline errors propagate to wrap().
   */
  wrap(async ({ workspace, repo, pull_request_id, content, file_path, line, start_line, line_side, parent_id }) => {
    const body = commentText(content);
    if (parent_id !== undefined) {
      // Reply: inherits the parent's location. Inline anchoring is ignored.
      body.parent = { id: parent_id };
      if (file_path || line !== undefined || start_line !== undefined) {
        return fail("A reply (parent_id) inherits its parent's location — don't also pass file_path/line/start_line. Drop them, or omit parent_id to make a new inline comment.");
      }
    } else if (file_path) {
      body.inline = buildInline({ file_path, line, start_line, line_side });
    } else if (line !== undefined || start_line !== undefined) {
      return fail("'line'/'start_line' require 'file_path' (inline comments need a file path). For a reply, pass 'parent_id' instead.");
    }
    const created = await bbWrite("POST", `/repositories/${enc(workspace)}/${enc(repo)}/pullrequests/${pull_request_id}/comments`, { body });
    return ok({
      id: created.id,
      created_on: created.created_on,
      parent_id: created.parent?.id,
      inline: created.inline ? { path: created.inline.path, from: created.inline.from, to: created.inline.to, start_from: created.inline.start_from, start_to: created.inline.start_to } : undefined,
      url: created.links?.html?.href,
    });
  })
);

server.registerTool(
  "update_pull_request_comment",
  {
    title: "Edit a pull request comment",
    description:
      "Replace the text of an existing pull request comment. Bitbucket only lets you edit comments YOU wrote. Only the text changes — the comment keeps its file/line anchor and its place in its thread. " +
      "'content' replaces the old text entirely; tag users with '@{account_id}' as in create_pull_request_comment. To add to a discussion rather than rewrite it, reply with create_pull_request_comment (parent_id) instead.",
    inputSchema: {
      workspace: slug,
      repo: slug,
      pull_request_id: z.number().int(),
      comment_id: z.number().int().describe("The comment to edit (an 'id' from get_pull_request_comments)"),
      content: z.string().min(1).describe("The new comment text (Bitbucket Markdown). Replaces the current text entirely."),
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
  },
  /**
   * Replace a comment's text (PUT .../comments/{cid}).
   * @param {{ workspace: string, repo: string, pull_request_id: number, comment_id: number, content: string }} args - Validated tool input.
   * @returns {Promise<object>} the tool result: the updated comment's summary and URL, or an isError
   *   result explaining a 403 (not your comment). Other failures propagate to wrap().
   */
  wrap(async ({ workspace, repo, pull_request_id, comment_id, content }) => {
    const path = `/repositories/${enc(workspace)}/${enc(repo)}/pullrequests/${pull_request_id}/comments/${comment_id}`;
    try {
      const updated = await bbWrite("PUT", path, { body: commentText(content) });
      return ok({ ...commentSummary(updated), url: updated.links?.html?.href });
    } catch (e) {
      if (e?.status === 403) {
        return fail(`[bitbucket-mcp] ${e.message}\nBitbucket only lets you edit your own comments, so comment ${comment_id} probably belongs to someone else.`);
      }
      throw e;
    }
  })
);

server.registerTool(
  "resolve_pull_request_comment",
  {
    title: "Resolve or reopen a comment thread",
    description:
      "Resolve a pull request comment thread, or reopen a resolved one. Pass the thread's TOP-LEVEL comment id: Bitbucket resolves whole threads, so a reply's id is refused with a pointer to its top-level comment (get_pull_request_comments with 'threaded' true shows which is which). " +
      "Resolving an already-resolved thread, or reopening an open one, reports that and changes nothing. To explain why you're resolving, first reply with create_pull_request_comment (parent_id).",
    inputSchema: {
      workspace: slug,
      repo: slug,
      pull_request_id: z.number().int(),
      comment_id: z.number().int().describe("The thread's top-level comment id (from get_pull_request_comments)"),
      action: z.enum([THREAD_ACTION.RESOLVE, THREAD_ACTION.REOPEN]).describe("'resolve' the thread, or 'reopen' a resolved one"),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  /**
   * Resolve or reopen a comment thread. Reads the comment first, so a reply is
   * refused (naming its top-level comment) and a no-op sends no write.
   * @param {{ workspace: string, repo: string, pull_request_id: number, comment_id: number, action: string }} args - Validated tool input;
   *   `action` is a THREAD_ACTION value.
   * @returns {Promise<object>} the tool result: `{ action, comment_id, result, ... }`, or an isError result
   *   for a reply. A 409 on resolve / 404 on reopen (a concurrent change) is reported as already done.
   */
  wrap(async ({ workspace, repo, pull_request_id, comment_id, action }) => {
    const commentsPath = `/repositories/${enc(workspace)}/${enc(repo)}/pullrequests/${pull_request_id}/comments`;
    const resolvePath = `${commentsPath}/${comment_id}/resolve`;
    // Read first: it catches a reply (which Bitbucket refuses with a bare 403) and
    // lets a no-op resolve/reopen succeed without a write.
    const comment = await bbGet(`${commentsPath}/${comment_id}`);
    if (comment.parent?.id !== undefined) {
      const rootId = await findThreadRootId(commentsPath, comment);
      return fail(
        `Comment ${comment_id} is a reply; Bitbucket only resolves a thread through its top-level comment. ` +
          (rootId ? `Pass comment_id ${rootId} instead.` : `Follow parent_id up from comment ${comment.parent.id} to find it.`)
      );
    }
    const isResolved = Boolean(comment.resolution);
    if (action === THREAD_ACTION.RESOLVE) {
      if (isResolved) return ok({ action, comment_id, result: "already resolved", resolved_by: comment.resolution.user?.display_name });
      try {
        const resolution = await bbWrite("POST", resolvePath);
        return ok({ action, comment_id, result: "resolved", resolved_by: resolution?.user?.display_name, resolved_on: resolution?.created_on });
      } catch (e) {
        if (e?.status === 409) return ok({ action, comment_id, result: "already resolved" }); // resolved between our read and write
        throw e;
      }
    }
    if (!isResolved) return ok({ action, comment_id, result: "already open (nothing to reopen)" });
    try {
      await bbWrite("DELETE", resolvePath);
      return ok({ action, comment_id, result: "reopened" });
    } catch (e) {
      if (e?.status === 404) return ok({ action, comment_id, result: "already open (nothing to reopen)" }); // reopened between our read and write
      throw e;
    }
  })
);

server.registerTool(
  "review_pull_request",
  {
    title: "Review a pull request",
    description:
      "Record YOUR review verdict on a pull request as the authenticated user. 'approve' and 'request-changes' are mutually exclusive states; setting one replaces the other. 'unapprove' withdraws your approval and 'unrequest-changes' withdraws your change request, each returning you to the neutral state. A comment-only review is just create_pull_request_comment with no verdict — this tool does NOT merge, decline, or comment.",
    inputSchema: {
      workspace: slug,
      repo: slug,
      pull_request_id: z.number().int(),
      action: z.enum(["approve", "unapprove", "request-changes", "unrequest-changes"]).describe("The review action to take"),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  wrap(async ({ workspace, repo, pull_request_id, action }) => {
    const sub = action === "approve" || action === "unapprove" ? "approve" : "request-changes";
    const method = action.startsWith("un") ? "DELETE" : "POST";
    const path = `/repositories/${enc(workspace)}/${enc(repo)}/pullrequests/${pull_request_id}/${sub}`;
    try {
      const result = await bbWrite(method, path);
      return ok({ action, pull_request_id, result: result ? participantSummary(result) : "removed" });
    } catch (e) {
      // Withdrawing a verdict you don't hold returns 404 — that's a no-op, not an error.
      if (method === "DELETE" && e?.status === 404) {
        return ok({ action, pull_request_id, result: "already in the neutral state (nothing to withdraw)" });
      }
      throw e;
    }
  })
);

server.registerTool(
  "create_pull_request",
  {
    title: "Create a pull request",
    description:
      "Open a new pull request. Requires 'title' and 'source_branch'; 'destination_branch' defaults to the repository's main branch. Provide a 'description' (Bitbucket Markdown). If you omit it and the repo defines a PR template, the template is applied automatically — prefer fetching it with get_pull_request_template first and writing a filled-in description. Optionally set reviewers (account_ids/UUIDs — look them up with list_workspace_members), close_source_branch, and draft.",
    inputSchema: {
      workspace: slug,
      repo: slug,
      title: z.string().describe("PR title"),
      source_branch: z.string().describe("The branch with your changes (the source)"),
      destination_branch: z.string().optional().describe("Target branch to merge into (defaults to the repo's main branch)"),
      description: z.string().optional().describe("PR description in Bitbucket Markdown. If omitted, a repo PR template is used when present (see use_template)."),
      reviewers: z.array(z.string()).optional().describe("Reviewer account_ids (e.g. '557058:...') or UUIDs (use list_workspace_members to find them). The PR author cannot be a reviewer."),
      close_source_branch: z.boolean().optional().describe("Delete the source branch after merge (default false)"),
      draft: z.boolean().optional().describe("Create the PR as a draft (default false)"),
      use_template: z.boolean().optional().describe("When 'description' is omitted, apply the repo's PR template if one exists (default true)"),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  },
  /**
   * Open a PR (POST .../pullrequests), applying the repo's PR template when no description is given.
   * @param {{ workspace: string, repo: string, title: string, source_branch: string, destination_branch?: string,
   *   description?: string, reviewers?: string[], close_source_branch?: boolean, draft?: boolean,
   *   use_template?: boolean }} args - Validated tool input.
   * @returns {Promise<object>} the tool result: the new PR's summary and description, plus `template_applied`
   *   (path or null) and, when a slashed branch couldn't be resolved, `template_skipped`. toReviewer errors
   *   propagate to wrap().
   */
  wrap(async ({ workspace, repo, title, source_branch, destination_branch, description, reviewers, close_source_branch, draft, use_template }) => {
    const body = {
      title,
      source: branchRef(source_branch),
    };
    if (destination_branch) body.destination = branchRef(destination_branch);

    let templateApplied = null;
    let templateSkipped = null;
    if (description !== undefined && description !== "") {
      body.description = description;
    } else if (use_template !== false) {
      // Resolve to a commit hash first; the Source API can't read a slashed
      // branch name, so don't pretend to have checked one we couldn't resolve.
      const hash = await resolveBranchHash(workspace, repo, source_branch);
      if (hash || !source_branch.includes("/")) {
        const tpl = await findPullRequestTemplate(workspace, repo, hash || source_branch);
        if (tpl) {
          body.description = tpl.content;
          templateApplied = tpl.path;
        }
      } else {
        templateSkipped = "Could not resolve the source branch's head commit; template not applied (branch name contains '/'). Pass 'description' explicitly.";
      }
    }

    if (reviewers && reviewers.length) body.reviewers = reviewers.map(toReviewer);
    if (close_source_branch !== undefined) body.close_source_branch = close_source_branch;
    if (draft !== undefined) body.draft = draft;

    const created = await bbWrite("POST", `/repositories/${enc(workspace)}/${enc(repo)}/pullrequests`, { body });
    return ok({
      ...prSummary(created),
      template_applied: templateApplied,
      ...(templateSkipped ? { template_skipped: templateSkipped } : {}),
      description: created.summary?.raw ?? created.description,
    });
  })
);

server.registerTool(
  "update_pull_request",
  {
    title: "Update a pull request",
    description:
      "Edit an OPEN pull request. Pass only what you want to change: 'title', 'description', 'add_reviewers' / 'remove_reviewers', 'draft' (false marks it ready for review, true converts it back to a draft), or 'destination_branch' (retarget). " +
      "Everything else stays as it is, including current reviewers unless you remove them. 'description' REPLACES the whole description, so to change part of it, read it with get_pull_request first and send the full edited text. " +
      "Reviewers are account_ids or UUIDs: get_pull_request lists current reviewers' account_ids and uuids, and list_workspace_members finds new ones. The PR author can't be a reviewer. " +
      "This tool cannot merge, decline, change the source branch, or change close_source_branch.",
    inputSchema: {
      workspace: slug,
      repo: slug,
      pull_request_id: z.number().int(),
      title: z.string().min(1).optional().describe("New PR title"),
      description: z.string().optional().describe('New PR description in Bitbucket Markdown. Replaces the current one entirely; pass "" to clear it.'),
      add_reviewers: z.array(z.string()).optional().describe("account_ids or UUIDs to add as reviewers (people already reviewing are skipped)"),
      remove_reviewers: z.array(z.string()).optional().describe("account_ids or UUIDs to remove from the reviewers (each must currently be a reviewer)"),
      draft: z.boolean().optional().describe("false marks a draft PR ready for review; true converts it back to a draft"),
      destination_branch: z.string().min(1).optional().describe("Retarget the PR to merge into this branch"),
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
  },
  /**
   * Edit an open PR: read it, build the PUT body (buildPullRequestUpdate), write,
   * then compare before/after (findUnexpectedChanges).
   * @param {{ workspace: string, repo: string, pull_request_id: number }} args - Validated tool input, plus the
   *   optional changes buildPullRequestUpdate takes (title, description, add_reviewers, remove_reviewers,
   *   draft, destination_branch).
   * @returns {Promise<object>} the tool result: the updated PR summary, `updated`, and — if Bitbucket changed
   *   anything not requested — `unexpected_changes` plus a warning. isError for a non-OPEN PR or a rejected
   *   reviewer list; builder errors (nothing to update, unknown reviewer) propagate to wrap().
   */
  wrap(async ({ workspace, repo, pull_request_id, ...changes }) => {
    const path = `/repositories/${enc(workspace)}/${enc(repo)}/pullrequests/${pull_request_id}`;
    const current = await bbGet(path);
    if (current.state !== PR_STATE_OPEN) {
      return fail(`PR #${pull_request_id} is ${current.state}; Bitbucket only allows editing OPEN pull requests.`);
    }
    const { body, updated } = buildPullRequestUpdate(current, changes);
    try {
      const pr = await bbWrite("PUT", path, { body });
      const unexpected = findUnexpectedChanges(current, pr, updated);
      return ok({
        ...prSummary(pr),
        updated,
        description: pr.summary?.raw ?? pr.description,
        reviewers: (pr.reviewers || []).map(reviewerSummary),
        ...(unexpected.length
          ? {
              unexpected_changes: unexpected,
              warning:
                "Bitbucket changed fields that weren't requested — see unexpected_changes for each one's previous value and how it can be restored. Tell the user before doing anything else.",
            }
          : {}),
      });
    } catch (e) {
      if (e?.status === 400 && /reviewer/i.test(e.body ?? "")) {
        return fail(
          `[bitbucket-mcp] ${e.message}\nBitbucket rejected the reviewer list. A reviewer can't be the PR author, must have access to the repo, and must be an active user — and a current reviewer who has since been deactivated can make edits fail until you remove them with remove_reviewers.`
        );
      }
      throw e;
    }
  })
);

// Connect to stdio only when run directly (`node server.js` or via the npm bin
// symlink). When imported by a test, this is skipped so the module loads without
// holding the transport open. realpathSync resolves the bin symlink to this file.
const invokedDirectly = (() => {
  try {
    return Boolean(process.argv[1]) && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
})();

if (invokedDirectly) {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write("[bitbucket-mcp] MCP server running (read + PR comment/thread/review/create/update tools).\n");
}

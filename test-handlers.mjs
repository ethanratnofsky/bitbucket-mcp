#!/usr/bin/env node
/**
 * Behavioural tests for the PR-update and comment-thread tools: each tool is
 * called through a real MCP client over an in-memory transport, with the global
 * fetch replaced by an in-memory fake of the Bitbucket endpoints. Asserts the
 * exact requests sent (method, path, body) — including that no-op and refused
 * calls send NO write — and the results returned. No network, no creds.
 */

process.env.ATLASSIAN_USER_EMAIL ||= "test@example.com";
process.env.ATLASSIAN_API_TOKEN ||= "dummy-token";

const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");
const { InMemoryTransport } = await import("@modelcontextprotocol/sdk/inMemory.js");
const { server } = await import("./server.js");

const PR_PREFIX = /^\/2\.0\/repositories\/acme\/(app|code-reviewer)\/pullrequests/;
const ALICE = { display_name: "Alice", account_id: "557058:alice", uuid: "{aaaaaaaa-0000-0000-0000-000000000001}" };
const BOB = { display_name: "Bob", account_id: "557058:bob", uuid: "{bbbbbbbb-0000-0000-0000-000000000002}" };

/** @type {Array<{ method: string, path: string, body?: unknown }>} */
let requests = [];
let prs;
let comments;

/**
 * Reset the fake Bitbucket state and the request log before each scenario.
 * PR 42 is open, 43 is merged, and 44 is open but its PUT "forgets"
 * close_source_branch (to exercise the tripwire). Comment 1 is an open root,
 * 2 replies to 1, 4 replies to 2, 3 is a resolved root, 5 resolves "concurrently"
 * (its POST /resolve answers 409), and 99 belongs to someone else (PUT → 403).
 * @returns {void}
 */
const reset = () => {
  requests = [];
  const base = {
    title: "Old title",
    summary: { raw: "Old body" },
    description: "Old body",
    state: "OPEN",
    draft: false,
    close_source_branch: true,
    destination: { branch: { name: "main" } },
    reviewers: [ALICE, BOB],
  };
  prs = { 42: { ...base, id: 42 }, 43: { ...base, id: 43, state: "MERGED" }, 44: { ...base, id: 44 } };
  comments = {
    1: { id: 1, content: { raw: "root" } },
    2: { id: 2, content: { raw: "reply" }, parent: { id: 1 } },
    4: { id: 4, content: { raw: "reply to reply" }, parent: { id: 2 } },
    3: { id: 3, content: { raw: "done" }, resolution: { type: "comment_resolution", user: { display_name: "Bob" } } },
    5: { id: 5, content: { raw: "racing" } },
    99: { id: 99, content: { raw: "not mine" } },
  };
};

/**
 * Build a JSON Response the way Bitbucket would send it.
 * @param {number} status - HTTP status.
 * @param {unknown} [body] - JSON body; omitted for a bodiless response.
 * @returns {Response} the fake response.
 */
const reply = (status, body) =>
  new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

/**
 * Map a reviewer ref from a PUT body back to the full fake user, as Bitbucket would.
 * @param {{ uuid?: string, account_id?: string }} r - A reviewer ref.
 * @returns {object} the matching fake user, or a bare `{ account_id }` user for someone the fake doesn't know.
 */
const byRef = (r) => [ALICE, BOB].find((u) => u.uuid === r.uuid || u.account_id === r.account_id) ?? { account_id: r.account_id };

/**
 * Fake Bitbucket: logs every request, then answers the PR, comment, and resolve
 * endpoints from the in-memory state that reset() builds. Anything else is a 500
 * so an unexpected request fails loudly.
 * @param {string|URL} url - Request URL.
 * @param {RequestInit} [init] - Request options (method, JSON body).
 * @returns {Promise<Response>} the fake response.
 */
globalThis.fetch = async (url, init = {}) => {
  const { pathname } = new URL(url);
  const method = init.method || "GET";
  const body = init.body ? JSON.parse(init.body) : undefined;
  requests.push({ method, path: pathname, ...(body !== undefined ? { body } : {}) });
  if (!PR_PREFIX.test(pathname)) return reply(500, { error: { message: `fake: unexpected ${method} ${pathname}` } });
  const p = pathname.replace(PR_PREFIX, "");
  let m;
  if ((m = p.match(/^\/(\d+)$/))) {
    const pr = prs[m[1]];
    if (method === "GET") return reply(200, pr);
    if (method === "PUT") {
      if (body.destination?.branch?.name === "missing") return reply(400, { error: { message: "destination: branch not found" } });
      if (body.title === "bad-reviewer") return reply(400, { error: { message: "reviewers: Malformed reviewers list" } });
      Object.assign(pr, body, { reviewers: body.reviewers.map(byRef) });
      if (body.description !== undefined) pr.summary = { raw: body.description };
      if (pr.id === 44) pr.close_source_branch = false;
      return reply(200, pr);
    }
  }
  if (p === "/42/comments" && method === "GET") return reply(200, { values: [1, 2, 3, 4].map((id) => comments[id]) });
  // PR 45: a listing that repeats comment 2, as a page boundary shifting under new comments could.
  if (p === "/45/comments" && method === "GET") return reply(200, { values: [1, 2, 2, 4].map((id) => comments[id]) });
  if ((m = p.match(/^\/42\/comments\/(\d+)$/))) {
    const c = comments[m[1]];
    if (method === "GET") return reply(200, c);
    if (method === "PUT") return m[1] === "99" ? reply(403, { error: { message: "forbidden" } }) : reply(200, { ...c, content: body.content });
  }
  if ((m = p.match(/^\/42\/comments\/(\d+)\/resolve$/))) {
    if (method === "POST") return m[1] === "5" ? reply(409, { error: { message: "already resolved" } }) : reply(200, { type: "comment_resolution", user: { display_name: "Me" } });
    if (method === "DELETE") return new Response(null, { status: 204 });
  }
  return reply(500, { error: { message: `fake: unhandled ${method} ${p}` } });
};

const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
await server.connect(serverTransport);
const client = new Client({ name: "test-handlers", version: "0" });
await client.connect(clientTransport);

/**
 * Call a tool against fresh fake state; input-validation failures (thrown or
 * returned) come back as an isError result so every scenario reads the same.
 * @param {string} name - Tool name.
 * @param {object} args - Tool arguments.
 * @returns {Promise<{ isError: boolean, text: string, json?: any, writes: Array<object> }>} the result,
 *   its parsed JSON (when it is JSON), and the non-GET requests the call sent.
 */
const call = async (name, args) => {
  reset();
  let result;
  try {
    result = await client.callTool({ name, arguments: args });
  } catch (e) {
    result = { isError: true, content: [{ type: "text", text: String(e?.message || e) }] };
  }
  const text = result.content?.[0]?.text ?? "";
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = undefined;
  }
  return { isError: Boolean(result.isError), text, json, writes: requests.filter((r) => r.method !== "GET") };
};

let failures = 0;
/**
 * Record one assertion, printing ok/FAIL like test.mjs.
 * @param {string} name - What is being checked.
 * @param {unknown} actual - Observed value.
 * @param {unknown} expected - Expected value (compared as JSON).
 * @returns {void}
 */
const check = (name, actual, expected) => {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  if (a === e) process.stdout.write(`  ok   ${name}\n`);
  else {
    failures++;
    process.stdout.write(`  FAIL ${name}\n       expected ${e}\n       got      ${a}\n`);
  }
};

const BASE = { workspace: "acme", repo: "app", pull_request_id: 42 };
const PR_PATH = "/2.0/repositories/acme/app/pullrequests/42";
const KEEP_REVIEWERS = [{ uuid: ALICE.uuid }, { uuid: BOB.uuid }];

process.stdout.write("update_pull_request:\n");
let r = await call("update_pull_request", { ...BASE, title: "New title" });
check("title-only edit sends title + echoed description + kept reviewers", r.writes, [
  { method: "PUT", path: PR_PATH, body: { title: "New title", description: "Old body", reviewers: KEEP_REVIEWERS } },
]);
check("…and reports only title as updated, with no warning", [r.json?.updated, r.json?.warning], [["title"], undefined]);
r = await call("update_pull_request", { ...BASE, add_reviewers: ["557058:carol"], remove_reviewers: ["557058:bob"], draft: true, destination_branch: "dev" });
check("reviewers/draft/destination edit sends the full requested body", r.writes[0]?.body, {
  title: "Old title",
  description: "Old body",
  reviewers: [{ uuid: ALICE.uuid }, { account_id: "557058:carol" }],
  draft: true,
  destination: { branch: { name: "dev" } },
});
r = await call("update_pull_request", { ...BASE });
check("an empty update is refused without a write", [r.isError, r.writes.length], [true, 0]);
r = await call("update_pull_request", { ...BASE, pull_request_id: 43, title: "x" });
check("a merged PR is refused without a write", [r.isError, r.writes.length, r.text.includes("MERGED")], [true, 0, true]);
r = await call("update_pull_request", { ...BASE, pull_request_id: 44, title: "x" });
check("tripwire flags a field the PUT reset (close_source_branch)", r.json?.unexpected_changes?.map((c) => c.field), ["close_source_branch"]);
check("…and says it can only be restored in the UI", r.json?.unexpected_changes?.[0]?.restore.includes("Bitbucket UI"), true);
r = await call("update_pull_request", { ...BASE, title: "bad-reviewer" });
check("a 400 about reviewers explains the usual causes", [r.isError, r.text.includes("A reviewer can't be the PR author")], [true, true]);
r = await call("update_pull_request", { ...BASE, repo: "code-reviewer", destination_branch: "missing" });
check("a 400 about something else doesn't (even in a repo named *reviewer*)", [r.isError, r.text.includes("A reviewer can't be")], [true, false]);
r = await call("update_pull_request", { ...BASE, workspace: "..", repo: "snippets", title: "x" });
check("a '..' workspace is rejected before any request", [r.isError, requests.length], [true, 0]);

process.stdout.write("update_pull_request_comment:\n");
r = await call("update_pull_request_comment", { ...BASE, comment_id: 1, content: "edited" });
check("sends only the new text", r.writes, [{ method: "PUT", path: `${PR_PATH}/comments/1`, body: { content: { raw: "edited" } } }]);
r = await call("update_pull_request_comment", { ...BASE, comment_id: 99, content: "edited" });
check("someone else's comment → 403 with an explanation", [r.isError, r.text.includes("your own comments")], [true, true]);
r = await call("update_pull_request_comment", { ...BASE, workspace: "..", repo: "snippets", comment_id: 5, content: "x" });
check("a '..' workspace is rejected before any request", [r.isError, requests.length], [true, 0]);

process.stdout.write("resolve_pull_request_comment:\n");
r = await call("resolve_pull_request_comment", { ...BASE, comment_id: 1, action: "resolve" });
check("resolves an open thread", [r.json?.result, r.writes], ["resolved", [{ method: "POST", path: `${PR_PATH}/comments/1/resolve` }]]);
r = await call("resolve_pull_request_comment", { ...BASE, comment_id: 3, action: "resolve" });
check("an already-resolved thread sends no write", [r.json?.result, r.writes.length], ["already resolved", 0]);
r = await call("resolve_pull_request_comment", { ...BASE, comment_id: 5, action: "resolve" });
check("a 409 (resolved concurrently) is reported as already resolved", [r.isError, r.json?.result], [false, "already resolved"]);
r = await call("resolve_pull_request_comment", { ...BASE, comment_id: 4, action: "resolve" });
check("a reply is refused without a write and names the root", [r.isError, r.writes.length, r.text.includes("comment_id 1")], [true, 0, true]);
r = await call("resolve_pull_request_comment", { ...BASE, comment_id: 3, action: "reopen" });
check("reopens a resolved thread", [r.json?.result, r.writes], ["reopened", [{ method: "DELETE", path: `${PR_PATH}/comments/3/resolve` }]]);
r = await call("resolve_pull_request_comment", { ...BASE, comment_id: 1, action: "reopen" });
check("reopening an open thread sends no write", [r.json?.result, r.writes.length], ["already open (nothing to reopen)", 0]);

process.stdout.write("get_pull_request_comments (threaded):\n");
r = await call("get_pull_request_comments", { ...BASE, threaded: true });
check("nests replies and keeps roots in order", r.json?.threads?.map((t) => [t.id, t.replies?.map((x) => x.id)]), [[1, [2]], [3, undefined]]);
check("nests a reply to a reply", r.json?.threads?.[0]?.replies?.[0]?.replies?.map((x) => x.id), [4]);
check("marks the resolved thread", r.json?.threads?.[1]?.resolved, true);
r = await call("get_pull_request_comments", { ...BASE, pull_request_id: 45, threaded: true });
check("a listing that repeats a comment id doesn't crash, and keeps it once", [r.isError, r.json?.threads?.[0]?.replies?.map((x) => x.id)], [false, [2]]);

process.stdout.write("get_pull_request:\n");
r = await call("get_pull_request", { ...BASE });
check("reviewers carry display_name, account_id, and uuid", r.json?.reviewers, [
  { display_name: "Alice", account_id: ALICE.account_id, uuid: ALICE.uuid },
  { display_name: "Bob", account_id: BOB.account_id, uuid: BOB.uuid },
]);

await client.close();
if (failures) {
  process.stderr.write(`\n${failures} handler test(s) FAILED.\n`);
  process.exit(1);
}
process.stdout.write("\nAll handler tests passed.\n");

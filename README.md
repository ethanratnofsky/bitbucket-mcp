# bitbucket-mcp

A Bitbucket Cloud MCP server you run yourself. It gives Claude Code and Claude Desktop a set of **read** tools (pull requests, diffs, repositories, branches, files, PR templates, workspace members) plus a small, audited set of **pull-request write** tools: comment (general, inline, **multi-line**, **@-mention**, or **reply**), take a review action (approve / request changes / withdraw), and create a pull request.

## Why this exists / capability boundary

This is the "build it yourself" option, so the capability boundary lives in code rather than only in a token scope. Verify each claim by reading `server.js` (no build step):

- **Reads are GET-only and single-egress.** Every read goes through `bbGet()`, which is hard-coded to `GET` and refuses any origin other than `https://api.bitbucket.org`. The diff endpoints 302 to a repository-level URL; `bbGet` follows redirects **manually and re-checks the origin on every hop**, so the `Authorization` header can never be sent off-host — the allowlist is what enforces this, not the HTTP client's redirect behavior. Credentials are never logged.
- **Writes are restricted to an allowlist.** Every write goes through `bbWrite()`, which (a) accepts only `POST` or `DELETE`, (b) checks the request path against `WRITE_ALLOWLIST` — a short, explicit list of pull-request endpoints — *before* making a request, and (c) like reads, uses `redirect: "manual"` and **refuses to follow any 3xx**, so a write can never be transparently redirected to a different endpoint with credentials attached. The permitted writes are exactly:

  | Method | Path | Action |
  | --- | --- | --- |
  | `POST` | `.../pullrequests` | create a pull request |
  | `POST` | `.../pullrequests/{id}/comments` | comment — general, inline, multi-line, @-mention, or reply (all one endpoint) |
  | `POST` | `.../pullrequests/{id}/approve` | approve |
  | `DELETE` | `.../pullrequests/{id}/approve` | un-approve |
  | `POST` | `.../pullrequests/{id}/request-changes` | request changes |
  | `DELETE` | `.../pullrequests/{id}/request-changes` | withdraw request-changes |

  Inline, multi-line, @-mention, and reply comments all use that single comments `POST` — they add request-body fields, not new endpoints — so the write boundary stays exactly these six.

- **What it deliberately cannot do.** There is **no** path that can **merge, decline, edit/update a PR, delete comments, delete or create branches, delete a repository, or change settings** — those endpoints are not in the allowlist, so `bbWrite()` rejects them even if a future code change or a malicious prompt tries to construct the path. The allowlist patterns are anchored, the PR id segment is constrained to digits, and the workspace/repo segments cannot contain a slash (enforced at three layers: the `slug` input schema rejects it, every call site percent-encodes it, and the anchored allowlist regex is the backstop), so a path cannot be redirected to a different sub-resource like `/merge`.
- **The boundary is tested.** `npm test` runs `test.mjs`, which asserts the allowlist permits the six writes above and refuses merge/decline/edit/delete/wrong-method/traversal attempts, and `test-tools.mjs`, which confirms every tool registers with a valid schema.
- **Pinned dependencies.** Only `@modelcontextprotocol/sdk` and `zod`, both pinned to exact versions. Install once and run your reviewed copy.
- **Credentials stay local.** Read from the environment, used only for the `Authorization` header, never logged or sent elsewhere.
- **Robust by default.** Every request has a timeout (`BITBUCKET_TIMEOUT_MS`, default 30s) so a stalled connection can't hang the server. Reads (`GET`) retry with backoff on `429`/`502`/`503`/`504`, honoring `Retry-After`; writes are **never** auto-retried (a retried `POST` could double-post a comment or PR). List/comment reads auto-paginate up to a bounded number of pages and report `has_more`.

The token's `pullrequest` write scope (required by Bitbucket to comment, review, or create) would, in general, also permit merge and decline — but this server is the boundary: it exposes only the six writes above and nothing destructive, even when prompted to.

## Prerequisites

- Node.js 18+ (`node -v`).
- A Bitbucket Cloud **scoped API token** (app passwords are being retired — fully deprecated 28 Jul 2026). Create one at <https://id.atlassian.com/manage-profile/security/api-tokens> → **"Create API token with scopes"** → product **Bitbucket**. Grant it access only to the repositories you need, set an expiry, and note the owning account's email. The token starts with `ATATT`.

### Token scopes (exact)

Pick the set for what you want the server to do. **Select every scope in the set — Bitbucket's scoped API tokens do _not_ imply one scope from another** (e.g. `read:pullrequest:bitbucket` does *not* grant repository read), so a partial set causes confusing 403s.

**Read-only** — every read tool works; `review_pull_request` and `create_pull_request` return 403:

```
read:repository:bitbucket
read:pullrequest:bitbucket
read:workspace:bitbucket
```

**Read + write** — the read-only set **plus** the write scope, enabling comment / review / create:

```
read:repository:bitbucket
read:pullrequest:bitbucket
read:workspace:bitbucket
write:pullrequest:bitbucket
```

What each scope covers in this server:

| Scope | Tools / calls it enables |
| --- | --- |
| `read:pullrequest:bitbucket` | `list_pull_requests`, `get_pull_request`, `get_pull_request_comments`, and the PR `diff`/`diffstat` endpoints |
| `read:repository:bitbucket` | `get_file`, `get_pull_request_template`, `list_repositories`, `list_branches`, repo lookups, **and the diff/diffstat 302 redirect target** — the diff tool 403s on the redirect without it, *even with* the PR scope |
| `read:workspace:bitbucket` | `list_workspace_members` (look up account_ids to @-mention or add as reviewers) |
| `write:pullrequest:bitbucket` | `review_pull_request` (approve / request-changes / withdraw) and `create_pull_request` |

Notes:

- **Use the granular `:bitbucket` scope names**, not the bare OAuth names (`pullrequest`, `repository`, …). Atlassian's docs show both vocabularies; scoped API tokens use the `:bitbucket` form.
- Per Atlassian's scope descriptions, **posting a comment** (`create_pull_request_comment`, including inline / multi-line / @-mention / reply) is covered by `read:pullrequest:bitbucket` ("plus the ability to comment"). Approving, requesting changes, and creating PRs require `write:pullrequest:bitbucket`. The read+write set above enables all of them; if a comment ever 403s on a read-only token, add `write:pullrequest:bitbucket`.

## Install (once)

Put these files in a folder, then from inside it:

```bash
npm install
npm test   # optional: verifies the write allowlist and that all tools register
```

Note the absolute path to `server.js` — you'll point your client at it.

## Configure Claude Code

```bash
claude mcp add \
  --env ATLASSIAN_USER_EMAIL=you@company.com \
  --env ATLASSIAN_API_TOKEN=ATATT_your_scoped_token \
  --transport stdio --scope user bitbucket \
  -- node /absolute/path/to/bitbucket-mcp/server.js
```

Then run `/mcp` inside Claude Code to confirm it connected.

## Configure Claude Desktop

Edit `claude_desktop_config.json`:
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "bitbucket": {
      "command": "node",
      "args": ["/absolute/path/to/bitbucket-mcp/server.js"],
      "env": {
        "ATLASSIAN_USER_EMAIL": "you@company.com",
        "ATLASSIAN_API_TOKEN": "ATATT_your_scoped_token"
      }
    }
  }
}
```

Fully quit and relaunch Claude Desktop (config changes load only on a full restart). If `node` isn't on the app's PATH, use the absolute path from `which node` as `command`.

## Tools

| Tool | Access | What it does |
| --- | --- | --- |
| `list_pull_requests` | read | List PRs for a repo (defaults to OPEN) |
| `get_pull_request` | read | Details for one PR — description, reviewers, per-reviewer approval state |
| `get_pull_request_comments` | read | Comments on a PR (general + inline) |
| `get_pull_request_diff` | read | Comprehensive diff: per-file summary + raw unified diff (scopable, truncating) |
| `get_pull_request_template` | read | Find and return a repo's PR template, if any |
| `list_repositories` | read | Repos in a workspace, optional name filter |
| `list_branches` | read | Branches in a repo, optional name filter |
| `list_workspace_members` | read | Find users (account_id + ready-to-paste `@{…}` mention) to tag or add as reviewers |
| `get_file` | read | Read a file at a branch/tag/commit (defaults to main branch) |
| `create_pull_request_comment` | **write** | Comment on a PR — general, inline, multi-line, @-mention, or reply |
| `review_pull_request` | **write** | Approve, request changes, or withdraw either |
| `create_pull_request` | **write** | Open a PR (auto-applies a repo PR template when no description is given) |

### `get_pull_request_diff` — reviewing a PR

Returns a structured per-file summary (from Bitbucket's diffstat: status + lines added/removed) plus, by default, the raw unified diff text.

- `path` — limit to one file or a list of files (string or array).
- `context` — lines of context around each change (Bitbucket default 3).
- `ignore_whitespace` — hide whitespace-only changes.
- `include_diff` — set `false` for just the per-file summary (no raw diff).
- `max_diff_chars` — large diffs are truncated to this many characters (default 200000) with a note; narrow with `path` or raise the cap.

### `create_pull_request_comment` — comments, inline, multi-line, mentions, replies

One tool, several modes (it always uses the single comments `POST`):

- **General comment** — just `content`. This is the equivalent of a GitHub "comment-only review": feedback with no approval change.
- **Inline comment** — add `file_path` and `line`. `line_side` picks which side of the diff `line` refers to: `new` (added side, the default) or `old` (removed side).
- **Multi-line inline comment** — also pass `start_line` (the first line of the range; `line` is the last). Bitbucket anchors the range on the chosen side (`start_to`/`to` for new, `start_from`/`from` for old).
- **Reply** — pass `parent_id` (a comment `id` from `get_pull_request_comments`). A reply inherits its parent's location, so don't also pass `file_path`/`line`.
- **@-mention / tag** — put the literal mention token `@{account_id}` anywhere in `content`. Get the token from `list_workspace_members` (its `mention` field is exactly this string). Bitbucket renders it as a clickable mention and notifies the user. `@username`/`@nickname` are *not* reliable via the API post-GDPR — use `@{account_id}`.

### `list_workspace_members` — tagging users and finding reviewers

Returns each member's `account_id`, `uuid`, `nickname`, `display_name`, and a ready-to-paste `mention` (`@{account_id}`). Filter by name with `query` (matched case-insensitively against display name / nickname). Two uses:

- **To tag someone in a comment**, copy their `mention` value straight into `create_pull_request_comment`'s `content`.
- **To add a reviewer** on `create_pull_request`, pass their `account_id` in `reviewers`.

Requires the token's `read:workspace:bitbucket` scope.

### `review_pull_request` — review actions

`action` is one of `approve`, `request-changes`, `unapprove`, `unrequest-changes`. It records *your* verdict as the authenticated user. `approve` and `request-changes` are mutually exclusive states — setting one replaces the other; the `un...` actions return you to the neutral state (withdrawing a verdict you don't hold is treated as a no-op, not an error). This does **not** merge, decline, or comment — use `create_pull_request_comment` to leave review notes alongside your verdict. (Bitbucket Cloud has no separate "comment-only review" verb and no API for batched/pending review comments — each comment posts immediately; a comment-only review is simply a comment with no verdict.)

### `create_pull_request` — opening a PR with a good description

Requires `title` and `source_branch`; `destination_branch` defaults to the repo's main branch. Optional: `description`, `reviewers` (account_ids or UUIDs — the author can't be a reviewer), `close_source_branch`, `draft`.

PR templates: Bitbucket Cloud natively reads `.bitbucket/pull_request_template.md` from the **source branch**; this server also checks common GitHub-style fallbacks (`.github/`, root, `docs/`). The recommended flow is to call `get_pull_request_template` first, write a filled-in `description` that follows it, then call `create_pull_request`. If you omit `description` and a template exists, its raw content is applied automatically (set `use_template: false` to opt out), and the response reports `template_applied`. (Template lookup resolves the source branch to its head commit; if that can't be resolved for a branch name containing a slash, the template is skipped and the response says so via `template_skipped` — pass `description` explicitly in that case.)

## Verify

Read path:

> list open pull requests in `acme/frontend-app`

Diff path:

> show me the diff for PR 123 in `acme/frontend-app`, summary plus the changes to `src/api/client.ts`

Comment path (inline, multi-line, mention, reply):

> on PR 123, add an inline comment on line 42 of `src/api/client.ts` saying "Consider extracting this into a helper."
>
> on PR 123, comment on lines 38–42 of `src/api/client.ts`: "This whole block can be one map()."
>
> on PR 123, leave a comment tagging Jane: "@Jane can you take a look?" (resolve "Jane" with `list_workspace_members`, then tag her account_id)
>
> reply to comment 98765 on PR 123 with "Good call — fixed."

Review path:

> approve PR 123 in `acme/frontend-app`
>
> request changes on PR 123

Create path:

> read the PR template for `acme/frontend-app`, then open a PR from `feature/x` into `main` titled "Add X", filling in the template

## Operating notes

- The token grants exactly what you can already see/do in Bitbucket — nothing more. Review actions are taken **as you**; approving via this server is the same as clicking Approve. Set an expiry and rotate periodically. A fitting token name: `claude-bitbucket-mcp`.
- Do not commit `.env` or your real token; credentials live in your client config.
- To preserve the capability boundary if you extend this: keep `bbGet` GET-only, route **every** write through `bbWrite`, and add a new endpoint to `WRITE_ALLOWLIST` only after deciding it belongs there. Deliberately omitted endpoints (merge, decline, edit, delete) are the boundary — adding them widens it. Update `test.mjs` whenever you change the allowlist.

## License

No license is granted — all rights reserved. The source is published so you can read, audit, and run your own copy; it is not licensed for redistribution or modification. If you'd like it under an open-source license (e.g. MIT), open an issue.

# bitbucket-mcp

A Bitbucket Cloud MCP server you run yourself. It gives Claude Code and Claude Desktop a set of **read** tools (pull requests, diffs, repositories, branches, files, PR templates, workspace members, comment threads) plus a small, audited set of **pull-request write** tools: comment (general, inline, **multi-line**, **@-mention**, or **reply**), **edit your own comments**, **resolve / reopen comment threads**, take a review action (approve / request changes / withdraw), create a pull request, and **update a pull request** (title, description, reviewers, draft ↔ ready, destination branch).

## Why this exists / capability boundary

This is the "build it yourself" option, so the capability boundary lives in code rather than only in a token scope. Verify each claim by reading `server.js` (no build step):

- **Reads are GET-only and single-egress.** Every read goes through `bbGet()`, which is hard-coded to `GET` and refuses any origin other than `https://api.bitbucket.org`. The diff endpoints 302 to a repository-level URL; `bbGet` follows redirects **manually and re-checks the origin on every hop**, so the `Authorization` header can never be sent off-host — the allowlist is what enforces this, not the HTTP client's redirect behavior. Credentials are never logged.
- **Writes are restricted to an allowlist.** Every write goes through `bbWrite()`, which (a) accepts only `POST`, `PUT`, or `DELETE`, (b) checks the request path — and, for the two `PUT`s, the request body's fields — against `WRITE_ALLOWLIST`, a short, explicit list of pull-request endpoints, *before* making a request, and (c) like reads, uses `redirect: "manual"` and **refuses to follow any 3xx**, so a write can never be transparently redirected to a different endpoint with credentials attached. The permitted writes are exactly:

  | Method | Path | Action |
  | --- | --- | --- |
  | `POST` | `.../pullrequests` | create a pull request |
  | `PUT` | `.../pullrequests/{id}` | update a PR — body may contain **only** `title`, `description`, `reviewers`, `draft`, and `destination: { branch: { name } }` |
  | `POST` | `.../pullrequests/{id}/comments` | comment — general, inline, multi-line, @-mention, or reply (all one endpoint) |
  | `PUT` | `.../pullrequests/{id}/comments/{cid}` | edit a comment — body may contain **only** `content: { raw }` |
  | `POST` | `.../pullrequests/{id}/comments/{cid}/resolve` | resolve a comment thread |
  | `DELETE` | `.../pullrequests/{id}/comments/{cid}/resolve` | reopen a comment thread |
  | `POST` | `.../pullrequests/{id}/approve` | approve |
  | `DELETE` | `.../pullrequests/{id}/approve` | un-approve |
  | `POST` | `.../pullrequests/{id}/request-changes` | request changes |
  | `DELETE` | `.../pullrequests/{id}/request-changes` | withdraw request-changes |

  Inline, multi-line, @-mention, and reply comments all use that single comments `POST` — they add request-body fields, not new endpoints — so the write boundary stays exactly these ten.

- **PUT bodies are field-allowlisted too.** Bitbucket's update-PR endpoint accepts the whole pull-request document, so the path alone isn't a tight enough boundary. `bbWrite()` refuses an update whose body carries any other field — `state`, `source`, `close_source_branch`, `merge_commit`, … — and refuses a `destination` that names anything but a branch (a different repository or commit). A comment edit may carry only the new text, so it can't re-anchor or re-parent a comment.
- **What it deliberately cannot do.** There is **no** path that can **merge, decline, delete a PR or a comment, change a PR's source branch / state / close-source-branch setting, delete or create branches, delete a repository, or change settings** — those endpoints and fields are not in the allowlist, so `bbWrite()` rejects them even if a future code change or a malicious prompt tries to construct the request. The allowlist patterns are anchored, the PR and comment id segments are constrained to digits, and the workspace/repo segments cannot contain a slash (enforced at three layers: the `slug` input schema rejects it, every call site percent-encodes it, and the anchored allowlist regex is the backstop), so a path cannot be redirected to a different sub-resource like `/merge`.
- **No emoji reactions.** Bitbucket Cloud's public REST API has no endpoint for reacting to comments (only Bitbucket Data Center has one), so this server can't add reactions. It deliberately doesn't use the undocumented endpoint the Bitbucket web UI calls: that's unsupported, can change without notice, and would sit outside the allowlist design.
- **The boundary is tested.** `npm test` runs `test.mjs`, which asserts the allowlist permits the ten writes above and refuses merge/decline/delete/wrong-method/traversal attempts and every out-of-bounds `PUT` body, and `test-tools.mjs`, which confirms every tool registers with a valid schema and that only the write tools drop the `readOnlyHint` annotation.
- **Pinned dependencies.** Only `@modelcontextprotocol/sdk` and `zod`, both pinned to exact versions. Install once and run your reviewed copy.
- **Credentials stay local.** Read from the environment, used only for the `Authorization` header, never logged or sent elsewhere.
- **Robust by default.** Every request has a timeout (`BITBUCKET_TIMEOUT_MS`, default 30s) so a stalled connection can't hang the server. Reads (`GET`) retry with backoff on `429`/`502`/`503`/`504`, honoring `Retry-After`; writes are **never** auto-retried (a retried `POST` could double-post a comment or PR). List/comment reads auto-paginate up to a bounded number of pages and report `has_more`.

The token's `pullrequest` write scope (required by Bitbucket to review, create, or update a PR) would, in general, also permit merge and decline — but this server is the boundary: it exposes only the ten writes above, never merge, decline, or delete, even when prompted to.

## Prerequisites

- Node.js 18+ (`node -v`).
- A Bitbucket Cloud **scoped API token** (app passwords are being retired — fully deprecated 28 Jul 2026). Create one at <https://id.atlassian.com/manage-profile/security/api-tokens> → **"Create API token with scopes"** → product **Bitbucket**. Grant it access only to the repositories you need, set an expiry, and note the owning account's email. The token starts with `ATATT`.

### Token scopes (exact)

Pick the set for what you want the server to do. **Select every scope in the set — Bitbucket's scoped API tokens do _not_ imply one scope from another** (e.g. `read:pullrequest:bitbucket` does *not* grant repository read), so a partial set causes confusing 403s.

**Read-only** — every read tool works; `review_pull_request`, `create_pull_request`, and `update_pull_request` return 403:

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
| `read:pullrequest:bitbucket` | `list_pull_requests`, `get_pull_request`, `get_pull_request_comments`, the PR `diff`/`diffstat` endpoints, and — per Atlassian's scope list — `create_pull_request_comment`, `update_pull_request_comment`, and `resolve_pull_request_comment` |
| `read:repository:bitbucket` | `get_file`, `list_directory`, `get_pull_request_template`, `list_repositories`, `list_branches`, repo lookups, **and the diff/diffstat 302 redirect target** — the diff tool 403s on the redirect without it, *even with* the PR scope |
| `read:workspace:bitbucket` | `list_workspace_members` (look up account_ids to @-mention or add as reviewers) |
| `write:pullrequest:bitbucket` | `review_pull_request` (approve / request-changes / withdraw), `create_pull_request`, and `update_pull_request` |

Notes:

- **Use the granular `:bitbucket` scope names**, not the bare OAuth names (`pullrequest`, `repository`, …). Atlassian's docs show both vocabularies; scoped API tokens use the `:bitbucket` form.
- Per Atlassian's scope descriptions, **posting, editing, and resolving comments** (`create_pull_request_comment`, including inline / multi-line / @-mention / reply; `update_pull_request_comment`; `resolve_pull_request_comment`) is covered by `read:pullrequest:bitbucket` ("plus the ability to comment"). Approving, requesting changes, creating PRs, and updating PRs require `write:pullrequest:bitbucket`. The read+write set above enables all of them; if a comment action ever 403s on a read-only token, add `write:pullrequest:bitbucket`.

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
    "Bitbucket": {
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
| `get_pull_request` | read | Details for one PR — description, reviewers (with account_ids), per-reviewer approval state |
| `get_pull_request_comments` | read | Comments on a PR (general + inline), flat or grouped into threads (`threaded: true`) |
| `get_pull_request_diff` | read | Comprehensive diff: per-file summary + raw unified diff (scopable, truncating) |
| `get_pull_request_template` | read | Find and return a repo's PR template, if any |
| `list_repositories` | read | Repos in a workspace, optional name filter |
| `list_branches` | read | Branches in a repo, optional name filter |
| `list_workspace_members` | read | Find users (account_id + ready-to-paste `@{…}` mention) to tag or add as reviewers |
| `get_file` | read | Read a file at a branch/tag/commit (defaults to main branch) |
| `list_directory` | read | List files/subdirectories at a path (defaults to root) so you can discover real paths instead of guessing; `max_depth` recurses a few levels |
| `create_pull_request_comment` | **write** | Comment on a PR — general, inline, multi-line, @-mention, or reply |
| `update_pull_request_comment` | **write** | Edit the text of a comment you wrote |
| `resolve_pull_request_comment` | **write** | Resolve a comment thread, or reopen a resolved one |
| `review_pull_request` | **write** | Approve, request changes, or withdraw either |
| `create_pull_request` | **write** | Open a PR (auto-applies a repo PR template when no description is given) |
| `update_pull_request` | **write** | Edit an open PR: title, description, add/remove reviewers, draft ↔ ready, destination branch |

Every tool carries MCP [tool annotations](https://modelcontextprotocol.io/specification/2025-06-18/server/tools#tool-annotations): read tools are marked `readOnlyHint: true`; write tools state `destructiveHint` (true only for the two that overwrite content: `update_pull_request` and `update_pull_request_comment`) and `idempotentHint`, so a client can decide how carefully to confirm each call.

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

### Working with comment threads

- **See threads** — `get_pull_request_comments` with `threaded: true` returns each top-level comment with its replies nested under `replies`, plus `resolved` / `resolved_by` on resolved threads. If `has_more` is true, some replies fell outside `limit`; a reply whose parent wasn't fetched is shown as its own root with `parent_not_fetched: true`.
- **Reply in a thread** — `create_pull_request_comment` with `parent_id` (any comment in the thread).
- **Edit a comment** — `update_pull_request_comment` with `comment_id` and the new `content`. The text is replaced entirely; the comment keeps its file/line anchor and its place in the thread. Bitbucket only lets you edit your own comments (anyone else's returns 403).
- **Resolve / reopen** — `resolve_pull_request_comment` with `comment_id` and `action: "resolve" | "reopen"`. Bitbucket resolves whole threads through the **top-level** comment; pass a reply's id and the tool refuses before writing and tells you the top-level comment's id. Resolving an already-resolved thread (or reopening an open one) reports that and changes nothing.
- **Reactions** — not available; see [the capability boundary](#why-this-exists--capability-boundary).

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

### `update_pull_request` — editing an open PR

Pass only what you want to change; everything else stays as it is. Bitbucket only allows editing **open** PRs (the tool says so up front for a merged/declined one).

- `title` — new title.
- `description` — new description in Bitbucket Markdown. It **replaces** the whole description (`""` clears it), so to change part of it, read it with `get_pull_request` first and send the full edited text.
- `add_reviewers` / `remove_reviewers` — account_ids or UUIDs. `get_pull_request` lists current reviewers' account_ids; `list_workspace_members` finds new ones. Adding someone already reviewing is a no-op; removing someone who isn't a reviewer fails before anything is written.
- `draft` — `false` marks a draft PR ready for review; `true` converts it back to a draft.
- `destination_branch` — retarget the PR to merge into a different branch.

The tool reads the PR first and always sends its current title and reviewer list (with your additions/removals applied) along with your changes. Bitbucket doesn't document whether a partial update keeps fields it leaves out, so this makes sure editing the title, say, can never drop the reviewers. As a tripwire, it also compares the PR before and after: if any field you didn't ask to change (description, reviewers, draft, destination, close-source-branch) comes back different, the response lists it under `unexpected_changes` with its previous value so it can be restored. It can't merge, decline, change the source branch, or change `close_source_branch`, and `bbWrite()` would refuse a body that tried. If Bitbucket rejects the reviewer list (`Malformed reviewers list`), the error explains the usual causes: the author added as a reviewer, a user without repo access, or a current reviewer who has since been deactivated (remove them with `remove_reviewers`).

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

Thread path:

> show the comment threads on PR 123 and resolve the ones I've addressed
>
> fix the typo in my comment 98766 on PR 123

Update path:

> on PR 123, rename it to "Add X (behind flag)", add Jane as a reviewer, and mark it ready for review

Review path:

> approve PR 123 in `acme/frontend-app`
>
> request changes on PR 123

Create path:

> read the PR template for `acme/frontend-app`, then open a PR from `feature/x` into `main` titled "Add X", filling in the template

## Operating notes

- The token grants exactly what you can already see/do in Bitbucket — nothing more. Review actions are taken **as you**; approving via this server is the same as clicking Approve. Set an expiry and rotate periodically. A fitting token name: `claude-bitbucket-mcp`.
- Do not commit `.env` or your real token; credentials live in your client config.
- To preserve the capability boundary if you extend this: keep `bbGet` GET-only, route **every** write through `bbWrite`, and add a new endpoint to `WRITE_ALLOWLIST` only after deciding it belongs there. Give any endpoint whose body decides what changes (like the PR `PUT`) a `body` rule that names the allowed fields. Deliberately omitted endpoints and fields (merge, decline, delete, a PR's state or source branch) are the boundary — adding them widens it. Update `test.mjs` whenever you change the allowlist.

## License

No license is granted — all rights reserved. The source is published so you can read, audit, and run your own copy; it is not licensed for redistribution or modification. If you'd like it under an open-source license (e.g. MIT), open an issue.

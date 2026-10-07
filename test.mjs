#!/usr/bin/env node
/**
 * Tests for the bits that matter most: the write allowlist (the security
 * boundary, including the PUT body-field rules), reviewer parsing, the
 * inline-comment builder (single + multi-line), the repo-path encoder, the
 * PR-update body builder, and the comment-thread builder. Pure functions only —
 * no network, no creds.
 * Run with `npm test`.
 *
 * A separate end-to-end check (that all tools register over MCP) lives in
 * test-tools.mjs and runs as part of `npm test` too.
 */

// Dummy creds so server.js loads past its env-var guard. The pure functions
// under test never use them, and importing does not open the stdio transport
// (server.js only connects when run directly).
process.env.ATLASSIAN_USER_EMAIL ||= "test@example.com";
process.env.ATLASSIAN_API_TOKEN ||= "dummy-token";

const {
  isWriteAllowed,
  toReviewer,
  slug,
  buildInline,
  encodeRepoPath,
  sliceFile,
  mapDirEntries,
  buildPullRequestUpdate,
  buildCommentThreads,
  findUnexpectedChanges,
} = await import("./server.js");

let failures = 0;
function check(name, actual, expected) {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  if (a === e) {
    process.stdout.write(`  ok   ${name}\n`);
  } else {
    failures++;
    process.stdout.write(`  FAIL ${name}\n       expected ${e}\n       got      ${a}\n`);
  }
}
function throws(name, fn) {
  try {
    fn();
    failures++;
    process.stdout.write(`  FAIL ${name}\n       expected it to throw, but it returned\n`);
  } catch {
    process.stdout.write(`  ok   ${name}\n`);
  }
}

const WS = "/repositories/acme/some-repo/pullrequests";

process.stdout.write("write allowlist — PERMITTED:\n");
check("create PR (POST .../pullrequests)", isWriteAllowed("POST", WS), true);
check("comment (POST .../42/comments)", isWriteAllowed("POST", `${WS}/42/comments`), true);
check("approve (POST .../42/approve)", isWriteAllowed("POST", `${WS}/42/approve`), true);
check("un-approve (DELETE .../42/approve)", isWriteAllowed("DELETE", `${WS}/42/approve`), true);
check("request-changes (POST .../42/request-changes)", isWriteAllowed("POST", `${WS}/42/request-changes`), true);
check("withdraw changes (DELETE .../42/request-changes)", isWriteAllowed("DELETE", `${WS}/42/request-changes`), true);
check("update PR title (PUT .../42)", isWriteAllowed("PUT", `${WS}/42`, { title: "t" }), true);
check(
  "update PR, every allowed field",
  isWriteAllowed("PUT", `${WS}/42`, {
    title: "t",
    description: "d",
    reviewers: [{ uuid: "{x}" }],
    draft: false,
    destination: { branch: { name: "main" } },
  }),
  true
);
check("edit comment text (PUT .../42/comments/5)", isWriteAllowed("PUT", `${WS}/42/comments/5`, { content: { raw: "x" } }), true);
check("resolve thread (POST .../42/comments/5/resolve)", isWriteAllowed("POST", `${WS}/42/comments/5/resolve`), true);
check("reopen thread (DELETE .../42/comments/5/resolve)", isWriteAllowed("DELETE", `${WS}/42/comments/5/resolve`), true);

process.stdout.write("write allowlist — REFUSED (the boundary):\n");
check("merge", isWriteAllowed("POST", `${WS}/42/merge`), false);
check("decline", isWriteAllowed("POST", `${WS}/42/decline`), false);
check("update PR with no body", isWriteAllowed("PUT", `${WS}/42`), false);
check("update PR with an empty body", isWriteAllowed("PUT", `${WS}/42`, {}), false);
check("update PR state (merge via PUT)", isWriteAllowed("PUT", `${WS}/42`, { title: "t", state: "MERGED" }), false);
check("update PR source branch", isWriteAllowed("PUT", `${WS}/42`, { source: { branch: { name: "x" } } }), false);
check("update PR close_source_branch", isWriteAllowed("PUT", `${WS}/42`, { close_source_branch: true }), false);
check("update PR destination repository", isWriteAllowed("PUT", `${WS}/42`, { destination: { repository: { full_name: "evil/repo" } } }), false);
check("update PR destination commit", isWriteAllowed("PUT", `${WS}/42`, { destination: { branch: { name: "main" }, commit: { hash: "abc" } } }), false);
check("update PR destination branch extra field", isWriteAllowed("PUT", `${WS}/42`, { destination: { branch: { name: "main", target: {} } } }), false);
check("update PR body is an array", isWriteAllowed("PUT", `${WS}/42`, [{ title: "t" }]), false);
check("PUT on the PR collection", isWriteAllowed("PUT", WS, { title: "t" }), false);
check("PATCH a PR (wrong method)", isWriteAllowed("PATCH", `${WS}/42`, { title: "t" }), false);
check("edit comment with no body", isWriteAllowed("PUT", `${WS}/42/comments/5`), false);
check("edit comment re-anchor (inline)", isWriteAllowed("PUT", `${WS}/42/comments/5`, { content: { raw: "x" }, inline: { path: "a" } }), false);
check("edit comment re-parent", isWriteAllowed("PUT", `${WS}/42/comments/5`, { content: { raw: "x" }, parent: { id: 1 } }), false);
check("edit comment extra content field", isWriteAllowed("PUT", `${WS}/42/comments/5`, { content: { raw: "x", html: "<b>" } }), false);
check("PUT on the comments collection", isWriteAllowed("PUT", `${WS}/42/comments`, { content: { raw: "x" } }), false);
check("non-numeric comment id", isWriteAllowed("PUT", `${WS}/42/comments/abc`, { content: { raw: "x" } }), false);
check("resolve with non-numeric comment id", isWriteAllowed("POST", `${WS}/42/comments/abc/resolve`), false);
check("resolve via PUT (wrong method)", isWriteAllowed("PUT", `${WS}/42/comments/5/resolve`, { content: { raw: "x" } }), false);
check("PUT on approve", isWriteAllowed("PUT", `${WS}/42/approve`, { title: "t" }), false);
check("delete PR (DELETE)", isWriteAllowed("DELETE", `${WS}/42`), false);
check("delete a comment", isWriteAllowed("DELETE", `${WS}/42/comments/5`), false);
check("delete the PR collection", isWriteAllowed("DELETE", WS), false);
check("approve as GET (wrong method)", isWriteAllowed("GET", `${WS}/42/approve`), false);
check("non-numeric id", isWriteAllowed("POST", `${WS}/abc/approve`), false);
check("trailing path past approve", isWriteAllowed("POST", `${WS}/42/approve/extra`), false);
check("traversal toward merge", isWriteAllowed("POST", `${WS}/42/approve/../merge`), false);
check("merge approvals (different repo path depth)", isWriteAllowed("POST", "/repositories/ws/repo/pullrequests/42/merge"), false);
check("workspace-level write", isWriteAllowed("POST", "/repositories/acme"), false);

process.stdout.write("write allowlist — REFUSED: paths the URL parser would rewrite:\n");
check(
  "'..' workspace → snippet comment PUT",
  isWriteAllowed("PUT", "/repositories/../snippets/pullrequests/42/comments/5", { content: { raw: "x" } }),
  false
);
check("'..' workspace → snippet comment POST", isWriteAllowed("POST", "/repositories/../snippets/pullrequests/42/comments"), false);
check("'.' repo → create-repository POST", isWriteAllowed("POST", "/repositories/victim/./pullrequests"), false);
check("'..' repo → update-repository PUT", isWriteAllowed("PUT", "/repositories/acme/../pullrequests/42", { title: "t" }), false);
check("%2e%2e segment", isWriteAllowed("PUT", "/repositories/%2e%2e/snippets/pullrequests/42/comments/5", { content: { raw: "x" } }), false);
check("%2E segment (upper case)", isWriteAllowed("POST", "/repositories/victim/%2E/pullrequests"), false);
check("backslash treated as a slash", isWriteAllowed("POST", "/repositories/a\\..\\b/repo/pullrequests"), false);
check("query string smuggled into the path", isWriteAllowed("POST", `${WS}?x=1`), false);
check("still allows a percent-encoded uuid slug", isWriteAllowed("POST", `/repositories/${encodeURIComponent("{504c3b62-8120-4f0c-a7bc-87800b9d6f70}")}/r/pullrequests/1/comments`), true);
check("still allows a dotted (non-dot-segment) slug", isWriteAllowed("POST", "/repositories/acme/my.repo/pullrequests/1/approve"), true);

process.stdout.write("slug input invariant (workspace/repo cannot contain '/' or be a dot segment):\n");
check("accepts a plain slug", slug.safeParse("acme").success, true);
check("accepts a brace-wrapped uuid", slug.safeParse("{504c3b62-8120-4f0c-a7bc-87800b9d6f70}").success, true);
check("accepts a slug containing dots", slug.safeParse("my.repo").success, true);
check("accepts '...' (not a dot segment)", slug.safeParse("...").success, true);
check("rejects a slash (path injection)", slug.safeParse("repo/42/merge").success, false);
check("rejects an encoded-looking slash payload", slug.safeParse("a/b").success, false);
check("rejects '.'", slug.safeParse(".").success, false);
check("rejects '..'", slug.safeParse("..").success, false);

process.stdout.write("toReviewer parsing:\n");
check("account_id with colon", toReviewer("557058:f0c3abcd-1234-5678-9abc-def012345678"), { account_id: "557058:f0c3abcd-1234-5678-9abc-def012345678" });
check("bare uuid → braces", toReviewer("504c3b62-8120-4f0c-a7bc-87800b9d6f70"), { uuid: "{504c3b62-8120-4f0c-a7bc-87800b9d6f70}" });
check("brace-wrapped uuid", toReviewer("{504c3b62-8120-4f0c-a7bc-87800b9d6f70}"), { uuid: "{504c3b62-8120-4f0c-a7bc-87800b9d6f70}" });
check("opaque account_id", toReviewer("712020:abc"), { account_id: "712020:abc" });
throws("rejects an email", () => toReviewer("jane@example.com"));
throws("rejects a display name with a space", () => toReviewer("Jane Doe"));
throws("rejects empty", () => toReviewer("   "));

process.stdout.write("buildInline (single + multi-line, new/old side):\n");
check("single line, new side (default)", buildInline({ file_path: "a.ts", line: 42 }), { path: "a.ts", to: 42 });
check("single line, old side", buildInline({ file_path: "a.ts", line: 42, line_side: "old" }), { path: "a.ts", from: 42 });
check("range, new side", buildInline({ file_path: "a.ts", start_line: 38, line: 42 }), { path: "a.ts", to: 42, start_to: 38 });
check("range, old side", buildInline({ file_path: "a.ts", start_line: 36, line: 40, line_side: "old" }), { path: "a.ts", from: 40, start_from: 36 });
check("start_line == line collapses to single line", buildInline({ file_path: "a.ts", start_line: 42, line: 42 }), { path: "a.ts", to: 42 });
check("file-level inline (no line)", buildInline({ file_path: "a.ts" }), { path: "a.ts" });
throws("rejects start_line > line", () => buildInline({ file_path: "a.ts", start_line: 50, line: 42 }));
throws("rejects start_line without line", () => buildInline({ file_path: "a.ts", start_line: 5 }));
throws("rejects missing file_path", () => buildInline({ line: 5 }));
throws("rejects bad line_side", () => buildInline({ file_path: "a.ts", line: 5, line_side: "left" }));
throws("rejects non-positive line", () => buildInline({ file_path: "a.ts", line: 0 }));

process.stdout.write("encodeRepoPath (segment-encode, preserve slashes, reject '..'):\n");
check("plain path untouched", encodeRepoPath("src/index.ts"), "src/index.ts");
check("strips leading slashes", encodeRepoPath("/src/index.ts"), "src/index.ts");
check("encodes spaces and specials", encodeRepoPath("src/my file#1.ts"), "src/my%20file%231.ts");
check("preserves nested slashes", encodeRepoPath("a/b/c/d.ts"), "a/b/c/d.ts");
throws("rejects a '..' segment", () => encodeRepoPath("src/../secret"));

process.stdout.write("sliceFile (whole-file passthrough, line windows, cap, past-EOF):\n");
const small = "L1\nL2\nL3";
check("small whole file returned verbatim", sliceFile(small), small);
check("no note on a small whole-file read", sliceFile(small).includes("[bitbucket-mcp]"), false);
check("empty file returned verbatim", sliceFile(""), "");
const five = "L1\nL2\nL3\nL4\nL5";
check("ranged read returns just the window", sliceFile(five, 2, 2).startsWith("L2\nL3"), true);
check("ranged read notes the shown range", sliceFile(five, 2, 2).includes("Showing lines 2-3 of 5"), true);
const big = Array.from({ length: 500 }, (_, i) => `x${i + 1}`).join("\n");
check("start_line without line_count uses the default window", sliceFile(big, 10).includes("Showing lines 10-409 of 500"), true);
const huge = Array.from({ length: 1000 }, () => "y".repeat(100)).join("\n");
const capped = sliceFile(huge);
check("oversized file is capped", capped.includes("capped to fit the read budget"), true);
check("capped output stays near the char limit", capped.length < 51_000, true);
check("capped output cut at a line boundary", capped.split("\n\n[bitbucket-mcp]")[0].endsWith("y".repeat(100)), true);
check("start_line past EOF is reported, not empty", sliceFile(five, 99).includes("past the end of the file (5 lines)"), true);

process.stdout.write("mapDirEntries (Bitbucket src listing → {path,type,size?}):\n");
check("maps a file with size", mapDirEntries([{ type: "commit_file", path: "a.ts", size: 12 }]), [{ path: "a.ts", type: "file", size: 12 }]);
check("maps a directory (no size)", mapDirEntries([{ type: "commit_directory", path: "src" }]), [{ path: "src", type: "directory" }]);
check(
  "mixed listing preserves order",
  mapDirEntries([{ type: "commit_directory", path: "src" }, { type: "commit_file", path: "README.md", size: 3 }]),
  [{ path: "src", type: "directory" }, { path: "README.md", type: "file", size: 3 }]
);
check("file without a numeric size omits size", mapDirEntries([{ type: "commit_file", path: "x" }]), [{ path: "x", type: "file" }]);
check("unknown entry type falls back to file", mapDirEntries([{ type: "commit_pr_thing", path: "y" }]), [{ path: "y", type: "file" }]);
check("nullish values yield an empty list", mapDirEntries(undefined), []);

process.stdout.write("buildPullRequestUpdate (only requested fields; title + reviewers always preserved):\n");
const ALICE = { display_name: "Alice", account_id: "557058:alice", uuid: "{aaaaaaaa-0000-0000-0000-000000000001}" };
const BOB = { display_name: "Bob", account_id: "557058:bob", uuid: "{bbbbbbbb-0000-0000-0000-000000000002}" };
const PR = { title: "Old title", state: "OPEN", reviewers: [ALICE, BOB] };
check(
  "title only: keeps reviewers, sends nothing else",
  buildPullRequestUpdate(PR, { title: "New" }),
  { body: { title: "New", reviewers: [{ uuid: ALICE.uuid }, { uuid: BOB.uuid }] }, updated: ["title"] }
);
check(
  "description only: echoes the current title",
  buildPullRequestUpdate(PR, { description: "Body" }).body,
  { title: "Old title", description: "Body", reviewers: [{ uuid: ALICE.uuid }, { uuid: BOB.uuid }] }
);
check("empty description clears it", buildPullRequestUpdate(PR, { description: "" }).body.description, "");
check(
  "add a reviewer appends; existing ones kept",
  buildPullRequestUpdate(PR, { add_reviewers: ["557058:carol"] }).body.reviewers,
  [{ uuid: ALICE.uuid }, { uuid: BOB.uuid }, { account_id: "557058:carol" }]
);
check(
  "adding someone already reviewing (by account_id) is a no-op",
  buildPullRequestUpdate(PR, { add_reviewers: ["557058:alice"] }).body.reviewers,
  [{ uuid: ALICE.uuid }, { uuid: BOB.uuid }]
);
check(
  "adding someone already reviewing (by bare UUID, any case) is a no-op",
  buildPullRequestUpdate(PR, { add_reviewers: ["AAAAAAAA-0000-0000-0000-000000000001"] }).body.reviewers,
  [{ uuid: ALICE.uuid }, { uuid: BOB.uuid }]
);
check(
  "duplicate adds collapse to one",
  buildPullRequestUpdate(PR, { add_reviewers: ["557058:carol", "557058:carol"] }).body.reviewers,
  [{ uuid: ALICE.uuid }, { uuid: BOB.uuid }, { account_id: "557058:carol" }]
);
check(
  "remove a reviewer by account_id",
  buildPullRequestUpdate(PR, { remove_reviewers: ["557058:bob"] }),
  { body: { title: "Old title", reviewers: [{ uuid: ALICE.uuid }] }, updated: ["reviewers"] }
);
check(
  "remove a reviewer by UUID",
  buildPullRequestUpdate(PR, { remove_reviewers: [ALICE.uuid] }).body.reviewers,
  [{ uuid: BOB.uuid }]
);
check(
  "remove everyone leaves an empty list (not omitted)",
  buildPullRequestUpdate(PR, { remove_reviewers: ["557058:alice", "557058:bob"] }).body.reviewers,
  []
);
check("PR with no reviewers sends an empty list", buildPullRequestUpdate({ title: "t" }, { title: "u" }).body.reviewers, []);
check(
  "draft false = ready for review",
  buildPullRequestUpdate(PR, { draft: false }),
  { body: { title: "Old title", reviewers: [{ uuid: ALICE.uuid }, { uuid: BOB.uuid }], draft: false }, updated: ["draft"] }
);
check(
  "destination branch is sent as { branch: { name } } only",
  buildPullRequestUpdate(PR, { destination_branch: "release/1.2" }).body.destination,
  { branch: { name: "release/1.2" } }
);
check(
  "every field at once",
  buildPullRequestUpdate(PR, {
    title: "T",
    description: "D",
    add_reviewers: ["557058:carol"],
    remove_reviewers: ["557058:bob"],
    draft: true,
    destination_branch: "dev",
  }).updated,
  ["title", "description", "reviewers", "draft", "destination"]
);
check(
  "every body it builds passes the allowlist",
  isWriteAllowed(
    "PUT",
    `${WS}/42`,
    buildPullRequestUpdate(PR, { title: "T", description: "D", add_reviewers: ["557058:carol"], draft: true, destination_branch: "dev" }).body
  ),
  true
);
throws("rejects an empty update", () => buildPullRequestUpdate(PR, {}));
throws("rejects empty reviewer arrays as the only change", () => buildPullRequestUpdate(PR, { add_reviewers: [], remove_reviewers: [] }));
throws("rejects removing someone who isn't a reviewer", () => buildPullRequestUpdate(PR, { remove_reviewers: ["557058:carol"] }));
throws("rejects adding and removing the same person", () =>
  buildPullRequestUpdate(PR, { add_reviewers: ["557058:alice"], remove_reviewers: ["557058:alice"] })
);
throws("rejects adding by account_id and removing by UUID (same person)", () =>
  buildPullRequestUpdate(PR, { add_reviewers: ["557058:alice"], remove_reviewers: [ALICE.uuid] })
);
throws("rejects a reviewer given as an email", () => buildPullRequestUpdate(PR, { add_reviewers: ["carol@example.com"] }));
const PR_WITH_BODY = { ...PR, summary: { raw: "Existing body" }, description: "Existing body" };
check(
  "title only on a PR with a description: echoes the description",
  buildPullRequestUpdate(PR_WITH_BODY, { title: "New" }).body,
  { title: "New", description: "Existing body", reviewers: [{ uuid: ALICE.uuid }, { uuid: BOB.uuid }] }
);
check("echoed description isn't reported as updated", buildPullRequestUpdate(PR_WITH_BODY, { title: "New" }).updated, ["title"]);
check("explicit description wins over the current one", buildPullRequestUpdate(PR_WITH_BODY, { description: "" }).body.description, "");

process.stdout.write("findUnexpectedChanges (tripwire for fields an update reset without being asked):\n");
const BEFORE = {
  title: "T",
  summary: { raw: "D" },
  reviewers: [ALICE, BOB],
  draft: true,
  destination: { branch: { name: "main" } },
  close_source_branch: true,
};
check("nothing changed → no warnings", findUnexpectedChanges(BEFORE, BEFORE, ["title"]), []);
check("requested changes aren't flagged", findUnexpectedChanges(BEFORE, { ...BEFORE, title: "New", draft: false }, ["title", "draft"]), []);
check("reviewer order doesn't matter", findUnexpectedChanges(BEFORE, { ...BEFORE, reviewers: [BOB, ALICE] }, ["title"]), []);
check(
  "a wiped description is flagged with its old value",
  findUnexpectedChanges(BEFORE, { ...BEFORE, summary: { raw: "" } }, ["title"]),
  [{ field: "description", before: "D", after: "", restore: "with update_pull_request, using the 'before' value" }]
);
const dropped = findUnexpectedChanges(BEFORE, { ...BEFORE, reviewers: [], close_source_branch: false }, ["title"]);
check("dropped reviewers and a reset close_source_branch are flagged", dropped.map((c) => c.field), ["reviewers", "close_source_branch"]);
check("close_source_branch says it can only be restored in the UI", dropped[1].restore.includes("Bitbucket UI"), true);

process.stdout.write("buildCommentThreads (flat comments → nested threads):\n");
check(
  "nests replies under their root, in order",
  buildCommentThreads([
    { id: 1, content: "root" },
    { id: 2, parent_id: 1, content: "reply" },
    { id: 3, content: "other root" },
    { id: 4, parent_id: 2, content: "reply to reply" },
    { id: 5, parent_id: 1, content: "second reply" },
  ]),
  [
    {
      id: 1,
      content: "root",
      replies: [
        { id: 2, parent_id: 1, content: "reply", replies: [{ id: 4, parent_id: 2, content: "reply to reply" }] },
        { id: 5, parent_id: 1, content: "second reply" },
      ],
    },
    { id: 3, content: "other root" },
  ]
);
check(
  "a reply whose parent wasn't fetched becomes a flagged root",
  buildCommentThreads([{ id: 9, parent_id: 7, content: "orphan" }]),
  [{ id: 9, parent_id: 7, content: "orphan", parent_not_fetched: true }]
);
check("no comments → no threads", buildCommentThreads([]), []);
const input = [{ id: 1 }, { id: 2, parent_id: 1 }];
buildCommentThreads(input);
check("does not mutate its input", input, [{ id: 1 }, { id: 2, parent_id: 1 }]);

if (failures) {
  process.stderr.write(`\n${failures} test(s) FAILED.\n`);
  process.exit(1);
}
process.stdout.write("\nAll allowlist / reviewer / inline / path / update / thread tests passed.\n");

#!/usr/bin/env node
/**
 * Tests for the bits that matter most: the write allowlist (the security
 * boundary), reviewer parsing, the inline-comment builder (single + multi-line),
 * and the repo-path encoder. Pure functions only — no network, no creds.
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

const { isWriteAllowed, toReviewer, slug, buildInline, encodeRepoPath } = await import("./server.js");

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

process.stdout.write("write allowlist — REFUSED (the boundary):\n");
check("merge", isWriteAllowed("POST", `${WS}/42/merge`), false);
check("decline", isWriteAllowed("POST", `${WS}/42/decline`), false);
check("edit/update PR (PUT)", isWriteAllowed("PUT", `${WS}/42`), false);
check("delete PR (DELETE)", isWriteAllowed("DELETE", `${WS}/42`), false);
check("delete a comment", isWriteAllowed("DELETE", `${WS}/42/comments/5`), false);
check("delete the PR collection", isWriteAllowed("DELETE", WS), false);
check("approve as GET (wrong method)", isWriteAllowed("GET", `${WS}/42/approve`), false);
check("non-numeric id", isWriteAllowed("POST", `${WS}/abc/approve`), false);
check("trailing path past approve", isWriteAllowed("POST", `${WS}/42/approve/extra`), false);
check("traversal toward merge", isWriteAllowed("POST", `${WS}/42/approve/../merge`), false);
check("merge approvals (different repo path depth)", isWriteAllowed("POST", "/repositories/ws/repo/pullrequests/42/merge"), false);
check("workspace-level write", isWriteAllowed("POST", "/repositories/acme"), false);

process.stdout.write("slug input invariant (workspace/repo cannot contain '/'):\n");
check("accepts a plain slug", slug.safeParse("acme").success, true);
check("accepts a brace-wrapped uuid", slug.safeParse("{504c3b62-8120-4f0c-a7bc-87800b9d6f70}").success, true);
check("rejects a slash (path injection)", slug.safeParse("repo/42/merge").success, false);
check("rejects an encoded-looking slash payload", slug.safeParse("a/b").success, false);

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

if (failures) {
  process.stderr.write(`\n${failures} test(s) FAILED.\n`);
  process.exit(1);
}
process.stdout.write("\nAll allowlist / reviewer / inline / path tests passed.\n");

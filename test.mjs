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

const { isWriteAllowed, toReviewer, slug, buildInline, encodeRepoPath, sliceFile, mapDirEntries } =
  await import("./server.js");

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

if (failures) {
  process.stderr.write(`\n${failures} test(s) FAILED.\n`);
  process.exit(1);
}
process.stdout.write("\nAll allowlist / reviewer / inline / path tests passed.\n");

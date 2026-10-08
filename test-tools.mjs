#!/usr/bin/env node
/**
 * End-to-end check: spawn server.js over stdio and confirm every tool registers
 * with a valid input schema (this also exercises the zod→JSON-schema conversion,
 * including the diff tool's union/enum params). No Bitbucket calls are made.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

const EXPECTED = [
  "list_pull_requests",
  "get_pull_request",
  "get_pull_request_comments",
  "get_pull_request_diff",
  "get_pull_request_template",
  "list_repositories",
  "list_branches",
  "list_workspace_members",
  "get_file",
  "list_directory",
  "create_pull_request_comment",
  "update_pull_request_comment",
  "resolve_pull_request_comment",
  "review_pull_request",
  "create_pull_request",
  "update_pull_request",
];

// The tools that can change anything in Bitbucket. Every other tool must
// declare itself read-only.
const WRITE_TOOLS = new Set([
  "create_pull_request_comment",
  "update_pull_request_comment",
  "resolve_pull_request_comment",
  "review_pull_request",
  "create_pull_request",
  "update_pull_request",
]);

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [join(here, "server.js")],
  env: {
    ...process.env,
    ATLASSIAN_USER_EMAIL: "test@example.com",
    ATLASSIAN_API_TOKEN: "dummy-token",
  },
});

const client = new Client({ name: "test", version: "0" });
await client.connect(transport);
const { tools } = await client.listTools();
await client.close();

const names = tools.map((t) => t.name).sort();
const missing = EXPECTED.filter((n) => !names.includes(n));
const extra = names.filter((n) => !EXPECTED.includes(n));
const noSchema = tools.filter((t) => !t.inputSchema || typeof t.inputSchema !== "object").map((t) => t.name);
const wrongHint = tools
  .filter((t) => t.annotations?.readOnlyHint !== !WRITE_TOOLS.has(t.name))
  .map((t) => t.name);

/**
 * Whether a JSON-schema string property enforces the workspace/repo slug rule:
 * it must carry a pattern that accepts a normal slug and a {uuid} but rejects
 * a slash, a dot segment, and a pre-encoded payload.
 * @param {object} [prop] - The property's JSON schema.
 * @returns {boolean} true when the pattern behaves like `slug`.
 */
const enforcesSlug = (prop) => {
  if (!prop?.pattern) return false;
  const re = new RegExp(prop.pattern);
  return (
    re.test("acme") &&
    re.test("{504c3b62-8120-4f0c-a7bc-87800b9d6f70}") &&
    !re.test("a/b") &&
    !re.test("..") &&
    !re.test(".") &&
    !re.test("a%2Fb")
  );
};
const unguardedSlug = tools
  .flatMap((t) => ["workspace", "repo"].filter((k) => t.inputSchema?.properties?.[k]).map((k) => [t.name, k]))
  .filter(([name, k]) => !enforcesSlug(tools.find((t) => t.name === name).inputSchema.properties[k]))
  .map(([name, k]) => `${name}.${k}`);

let failures = 0;
const line = (cond, msg) => {
  if (cond) process.stdout.write(`  ok   ${msg}\n`);
  else {
    failures++;
    process.stdout.write(`  FAIL ${msg}\n`);
  }
};

process.stdout.write(`registered ${tools.length} tools\n`);
line(missing.length === 0, `all expected tools present${missing.length ? ` (missing: ${missing.join(", ")})` : ""}`);
line(extra.length === 0, `no unexpected tools${extra.length ? ` (extra: ${extra.join(", ")})` : ""}`);
line(noSchema.length === 0, `every tool has an input schema${noSchema.length ? ` (missing: ${noSchema.join(", ")})` : ""}`);
line(wrongHint.length === 0, `every tool's readOnlyHint matches whether it writes${wrongHint.length ? ` (wrong: ${wrongHint.join(", ")})` : ""}`);
line(unguardedSlug.length === 0, `every workspace/repo input enforces the slug rule${unguardedSlug.length ? ` (missing: ${unguardedSlug.join(", ")})` : ""}`);

if (failures) {
  process.stderr.write(`\n${failures} tool-registration check(s) FAILED.\n`);
  process.exit(1);
}
process.stdout.write("\nAll tools registered with valid schemas.\n");

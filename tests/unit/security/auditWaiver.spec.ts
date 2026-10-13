import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const workspace = readFileSync(path.join(repoRoot, "pnpm-workspace.yaml"), "utf8");

const waivedAdvisories = [...workspace.matchAll(/^\s+- (GHSA-[\w-]+)\s*$/gm)].map(
  (match) => match[1],
);

// `pnpm audit --audit-level high` in CI only passes because of these waivers, so each one
// must name an owner and an expiry, and must stop passing once the expiry has gone by.
describe("dependency audit waivers", () => {
  it("records an owner and a future expiry for every waived advisory", () => {
    expect(waivedAdvisories.length).toBeGreaterThan(0);
    const expiry = /Expires: (\d{4}-\d{2}-\d{2})/.exec(workspace);
    expect(expiry, "waiver block must state `Expires: YYYY-MM-DD`").not.toBeNull();
    expect(workspace).toMatch(/Owner: repo maintainer/);
    expect(workspace).toMatch(/Remove when .* publishes a fix/);
    expect(new Date(`${expiry?.[1]}T00:00:00Z`).getTime()).toBeGreaterThan(Date.now());
  });

  it("names each waived advisory in the waiver comment", () => {
    for (const advisory of waivedAdvisories) {
      const occurrences = workspace.split(advisory).length - 1;
      expect(
        occurrences,
        `${advisory} needs a comment as well as the entry`,
      ).toBeGreaterThanOrEqual(2);
    }
  });
});

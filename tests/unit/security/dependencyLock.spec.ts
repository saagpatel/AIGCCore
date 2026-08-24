import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

const readRepoFile = (relativePath: string) =>
  readFileSync(path.join(repoRoot, relativePath), "utf8");

describe("dependency security overrides", () => {
  it("keeps Puppeteer's browser helper off the extract-zip dependency path", () => {
    const workspace = readRepoFile("pnpm-workspace.yaml");
    const lockfile = readRepoFile("pnpm-lock.yaml");

    expect(workspace).toContain("body-parser: 1.20.6");
    expect(workspace).toContain("nanoid: 3.3.18");
    expect(workspace).toContain("proxy-agent: 8.0.2");
    expect(workspace).toContain('"@puppeteer/browsers": 3.2.1');
    expect(lockfile).toContain("body-parser: 1.20.6");
    expect(lockfile).toContain("nanoid: 3.3.18");
    expect(lockfile).toContain("proxy-agent: 8.0.2");
    expect(lockfile).toContain("'@puppeteer/browsers': 3.2.1");
    expect(lockfile).toContain("'@puppeteer/browsers@3.2.1':");
    expect(lockfile).not.toMatch(/body-parser@1\.20\.5:/);
    expect(lockfile).not.toMatch(/extract-zip@/);
    expect(lockfile).not.toMatch(/nanoid@3\.3\.17:/);
    expect(lockfile).not.toMatch(/'@puppeteer\/browsers': 2\./);
  });
});

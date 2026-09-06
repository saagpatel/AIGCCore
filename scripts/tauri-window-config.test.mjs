import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { URL } from "node:url";

import { validateMainWindowConfig } from "./tauri-window-config.mjs";

const config = JSON.parse(
  await readFile(new URL("../src-tauri/tauri.conf.json", import.meta.url), "utf8"),
);

test("packaged desktop config defines one usable main window", () => {
  const mainWindow = validateMainWindowConfig(config);
  assert.equal(mainWindow.title, "AIGC Core");
  assert.equal(mainWindow.resizable, true);
});

test("window validation rejects a config with no desktop window list", () => {
  assert.throws(
    () => validateMainWindowConfig({ app: {} }),
    /app\.windows must define the desktop window list/,
  );
});

test("window validation rejects minimum dimensions larger than initial size", () => {
  assert.throws(
    () =>
      validateMainWindowConfig({
        app: {
          windows: [
            {
              label: "main",
              width: 800,
              height: 600,
              minWidth: 801,
              minHeight: 600,
            },
          ],
        },
      }),
    /minimum dimensions cannot exceed its initial size/,
  );
});

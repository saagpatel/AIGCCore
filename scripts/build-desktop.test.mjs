import assert from "node:assert/strict";
import test from "node:test";

import {
  buildInvocationForPlatform,
  runDesktopBuild,
} from "./build-desktop.mjs";

test("macOS canonical build emits only the app bundle", () => {
  assert.deepEqual(buildInvocationForPlatform("darwin"), {
    command: "pnpm",
    args: ["exec", "tauri", "build", "--bundles", "app"],
  });
});

test("Linux retains native default bundle targets", () => {
  assert.deepEqual(buildInvocationForPlatform("linux"), {
    command: "pnpm",
    args: ["exec", "tauri", "build"],
  });
});

test("Windows uses the executable shim and native default targets", () => {
  assert.deepEqual(buildInvocationForPlatform("win32"), {
    command: "pnpm.cmd",
    args: ["exec", "tauri", "build"],
  });
});

test("build runner propagates a non-zero child exit", () => {
  const spawn = () => ({ status: 7 });
  assert.equal(runDesktopBuild({ platform: "darwin", spawn }), 7);
});

test("build runner fails closed when the child cannot start", () => {
  const spawn = () => ({ error: new Error("missing pnpm") });
  assert.equal(runDesktopBuild({ platform: "linux", spawn }), 1);
});

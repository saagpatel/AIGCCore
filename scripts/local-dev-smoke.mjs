#!/usr/bin/env node
import { spawn } from "node:child_process";
import { mkdir } from "node:fs/promises";
import { request } from "node:http";
import { createServer } from "node:net";
import { dirname, resolve } from "node:path";
import { clearTimeout, setTimeout } from "node:timers";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

async function reservePort() {
  const server = createServer();
  await new Promise((accept, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", accept);
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  await new Promise((accept, reject) =>
    server.close((error) => (error ? reject(error) : accept())),
  );
  if (!port) throw new Error("failed to reserve a loopback port");
  return port;
}

function pageReady(port) {
  return new Promise((accept) => {
    const req = request(
      { host: "127.0.0.1", method: "GET", path: "/", port, timeout: 500 },
      (response) => {
        response.resume();
        accept(response.statusCode === 200);
      },
    );
    req.once("error", () => accept(false));
    req.once("timeout", () => {
      req.destroy();
      accept(false);
    });
    req.end();
  });
}

async function processGroupExists(pid) {
  try {
    process.kill(-pid, 0);
    return true;
  } catch (error) {
    if (error?.code === "ESRCH") return false;
    throw error;
  }
}

async function waitForExit(child, timeoutMs) {
  if (child.exitCode !== null || child.signalCode !== null) return true;
  return new Promise((accept) => {
    const timer = setTimeout(() => accept(false), timeoutMs);
    child.once("exit", () => {
      clearTimeout(timer);
      accept(true);
    });
  });
}

async function waitForProcessGroupToExit(pid, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!(await processGroupExists(pid))) return true;
    await delay(50);
  }
  return !(await processGroupExists(pid));
}

async function terminateExactProcessGroup(child) {
  if (!(await processGroupExists(child.pid))) return "already-exited";
  process.kill(-child.pid, "SIGTERM");
  await waitForExit(child, 5000);
  if (!(await waitForProcessGroupToExit(child.pid, 5000))) {
    process.kill(-child.pid, "SIGKILL");
    await waitForExit(child, 5000);
    if (!(await waitForProcessGroupToExit(child.pid, 5000))) {
      return "sigkill-group-still-present";
    }
    return "sigkill";
  }
  return "sigterm";
}

export async function main() {
  if (process.platform === "win32") {
    console.error("local development smoke currently requires POSIX process groups");
    return 2;
  }
  const port = await reservePort();
  const buildRoot = resolve(
    process.env.AIGCCORE_LOCAL_BUILD_ROOT ?? resolve(repositoryRoot, ".local-build"),
  );
  await mkdir(resolve(buildRoot, "vite-cache"), { recursive: true });
  const child = spawn(
    "pnpm",
    ["exec", "vite", "--host", "127.0.0.1", "--port", String(port), "--strictPort"],
    {
      cwd: repositoryRoot,
      detached: true,
      env: {
        ...process.env,
        VITE_CACHE_DIR: resolve(buildRoot, "vite-cache"),
        VITE_HOST: "127.0.0.1",
        VITE_PORT: String(port),
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => {
    stdout += chunk.toString();
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString();
  });
  const timeoutMs = Number(process.env.AIGCCORE_LOCAL_DEV_TIMEOUT_MS ?? "20000");
  let ready = false;
  let remainingProcessGroup = true;
  let termination = "not-attempted";
  const deadline = Date.now() + timeoutMs;
  try {
    while (Date.now() < deadline && child.exitCode === null) {
      if (await pageReady(port)) {
        ready = true;
        break;
      }
      await delay(100);
    }
  } finally {
    termination = await terminateExactProcessGroup(child);
    remainingProcessGroup = await processGroupExists(child.pid);
  }
  if (!ready || remainingProcessGroup) {
    console.error(
      JSON.stringify({
        ready,
        remaining_process_group: remainingProcessGroup,
        stderr_tail: stderr.slice(-1000),
        stdout_tail: stdout.slice(-1000),
        termination,
      }),
    );
    return 1;
  }
  console.log(
    JSON.stringify({
      host: "127.0.0.1",
      lifecycle: "exact-child-process-group",
      port,
      ready: true,
      remaining_process_group: false,
      status: "PASS",
      termination,
    }),
  );
  return 0;
}

try {
  process.exitCode = await main();
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}

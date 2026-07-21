"use strict";

const childProcess = require("child_process");
const dgram = require("dgram");
const fs = require("fs");
const fsp = fs.promises;
const net = require("net");
const path = require("path");

const mode = process.argv[2] || "safe";
const workspace = "/workspace";
const project = path.join(workspace, "project");
const report = {
  fixture_version: "AIGC_LOCAL_EXECUTION_FIXTURE_V1",
  mode,
  effects: {},
  environment: {},
  workspace_bytes: 0,
};

async function attempt(name, operation) {
  process.stderr.write(`AIGC_FIXTURE_STEP=${name}:begin\n`);
  try {
    const detail = await operation();
    report.effects[name] = {
      attempted: true,
      allowed: true,
      detail: detail === undefined ? "allowed" : String(detail),
    };
  } catch (error) {
    report.effects[name] = {
      attempted: true,
      allowed: false,
      detail: `${error.code || error.name || "ERROR"}:${error.message}`,
    };
  }
  process.stderr.write(`AIGC_FIXTURE_STEP=${name}:end\n`);
}

function listenAndExchange(options, nonce) {
  return new Promise((resolve, reject) => {
    let client;
    let settled = false;
    const server = net.createServer((socket) => {
      socket.once("data", (data) => socket.end(data));
    });
    const close = (socket) => {
      if (!socket) return;
      try {
        socket.destroy();
      } catch {
        // A denied socket may never enter the running state.
      }
    };
    const finish = (error, detail) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      close(client);
      try {
        server.close();
      } catch {
        // A denied listener is already closed.
      }
      if (error) reject(error);
      else resolve(detail);
    };
    server.once("error", (error) => finish(error));
    server.listen(options, () => {
      const address = server.address();
      const clientOptions =
        typeof address === "string"
          ? { path: address }
          : { host: options.host, port: address.port };
      client = net.createConnection(clientOptions);
      client.setTimeout(500);
      client.once("connect", () => client.write(nonce));
      client.once("data", (data) => {
        const received = data.toString("utf8");
        if (received === nonce) finish(null, "nonce-exchanged");
        else finish(new Error("nonce-mismatch"));
      });
      client.once("timeout", () => finish(new Error("socket-timeout")));
      client.once("error", (error) => finish(error));
    });
    const timer = setTimeout(() => finish(new Error("socket-timeout")), 750);
    timer.unref();
  });
}

function metadataProbe() {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({
      host: "169.254.169.254",
      port: 80,
    });
    socket.setTimeout(150);
    socket.once("connect", () => {
      socket.destroy();
      resolve("unexpected-metadata-connect");
    });
    socket.once("timeout", () => {
      socket.destroy();
      reject(new Error("metadata-timeout"));
    });
    socket.once("error", reject);
  });
}

function addressFamilyBind(host) {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    const timer = setTimeout(() => {
      server.close();
      reject(new Error("address-family-bind-timeout"));
    }, 500);
    timer.unref();
    server.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    server.listen({ host, port: 0 }, () => {
      const address = server.address();
      server.close(() => {
        clearTimeout(timer);
        resolve(`bound-family-${address.family}`);
      });
    });
  });
}

function dnsProtocolRoundTrip() {
  return new Promise((resolve, reject) => {
    const transactionId = 0xa16c;
    const labels = ["nonce-a16c", "aigc", "invalid"];
    const question = Buffer.concat([
      ...labels.map((label) =>
        Buffer.concat([Buffer.from([label.length]), Buffer.from(label, "ascii")]),
      ),
      Buffer.from([0, 0, 1, 0, 1]),
    ]);
    const query = Buffer.alloc(12 + question.length);
    query.writeUInt16BE(transactionId, 0);
    query.writeUInt16BE(0x0100, 2);
    query.writeUInt16BE(1, 4);
    question.copy(query, 12);
    const server = dgram.createSocket("udp4");
    const client = dgram.createSocket("udp4");
    let settled = false;
    const close = (socket) => {
      try {
        socket.close();
      } catch {
        // A denied socket may never enter the running state.
      }
    };
    const finish = (error, detail) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      close(client);
      close(server);
      if (error) reject(error);
      else resolve(detail);
    };
    server.once("error", (error) => finish(error));
    client.once("error", (error) => finish(error));
    server.once("message", (message, remote) => {
      if (
        message.length !== query.length ||
        message.readUInt16BE(0) !== transactionId ||
        message.readUInt16BE(4) !== 1
      ) {
        finish(new Error("dns-query-identity-mismatch"));
        return;
      }
      const response = Buffer.from(message);
      response.writeUInt16BE(0x8180, 2);
      server.send(response, remote.port, remote.address);
    });
    client.once("message", (message) => {
      if (
        message.readUInt16BE(0) === transactionId &&
        message.readUInt16BE(2) === 0x8180 &&
        message.subarray(12).equals(question)
      ) {
        finish(null, "dns-query-response-nonce-exchanged");
      } else finish(new Error("dns-response-identity-mismatch"));
    });
    server.bind(0, "127.0.0.1", () => {
      const address = server.address();
      client.send(query, address.port, "127.0.0.1");
    });
    const timer = setTimeout(
      () => finish(new Error("dns-transport-timeout")),
      500,
    );
    timer.unref();
  });
}

function proxyRoundTrip() {
  const configured =
    process.env.HTTPS_PROXY || "http://127.0.0.1:39091";
  const match = /^http:\/\/(127\.0\.0\.1):([0-9]+)$/.exec(configured);
  if (!match) {
    return Promise.reject(new Error("proxy-endpoint-not-run-owned-loopback"));
  }
  return new Promise((resolve, reject) => {
    const request =
      "GET http://nonce-a16c.aigc.invalid/ HTTP/1.1\r\nHost: nonce-a16c.aigc.invalid\r\n\r\n";
    const server = net.createServer((socket) => {
      socket.once("data", (data) => {
        if (data.toString("ascii") !== request) {
          socket.destroy();
          reject(new Error("proxy-request-identity-mismatch"));
          return;
        }
        socket.end("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
      });
    });
    const timer = setTimeout(() => {
      server.close();
      reject(new Error("proxy-round-trip-timeout"));
    }, 750);
    timer.unref();
    server.once("error", reject);
    server.listen({ host: match[1], port: Number(match[2]) }, () => {
      const client = net.createConnection({
        host: match[1],
        port: Number(match[2]),
      });
      client.once("connect", () => client.write(request));
      client.once("data", (data) => {
        if (!data.toString("ascii").startsWith("HTTP/1.1 204")) {
          reject(new Error("proxy-response-identity-mismatch"));
          return;
        }
        clearTimeout(timer);
        client.destroy();
        server.close(() => resolve("proxy-http-nonce-exchanged"));
      });
      client.once("error", reject);
    });
  });
}

function spawnDoubleForkedDelayedChild(delaySeconds) {
  const delayedScript = `sleep ${delaySeconds}; printf 'late\\n' > ${JSON.stringify(
    path.join(workspace, "delayed-canary"),
  )}; sleep 10`;
  const delayed = childProcess.spawn(
    "/bin/sh",
    ["-c", `( /bin/sh -c ${JSON.stringify(delayedScript)} ) & exit 0`],
    { detached: true, stdio: "ignore" },
  );
  delayed.unref();
}

async function runFixture() {
  if (mode === "benchmark") {
    await new Promise((resolve) => setTimeout(resolve, 5_000));
    process.stdout.write(
      'AIGC_FIXTURE_REPORT={"fixture_version":"AIGC_LOCAL_EXECUTION_FIXTURE_V1","mode":"benchmark","effects":{}}\n',
    );
    return;
  }
  if (mode === "performance") {
    await new Promise((resolve) => setTimeout(resolve, 250));
    process.stdout.write(
      'AIGC_FIXTURE_REPORT={"fixture_version":"AIGC_LOCAL_EXECUTION_FIXTURE_V1","mode":"performance","effects":{}}\n',
    );
    return;
  }

  await fsp.mkdir(project, { recursive: true, mode: 0o700 });
  await fsp.mkdir(path.join(workspace, "home"), {
    recursive: true,
    mode: 0o700,
  });

  await attempt("workspace_write", async () => {
    await fsp.writeFile(path.join(project, "allowed.txt"), "qualified-change\n", {
      mode: 0o600,
    });
    return "allowed.txt";
  });
  await attempt("immutable_input_write", () =>
    fsp.writeFile("/input/base.txt", "mutated\n"),
  );
  await attempt("host_path_write", () =>
    fsp.writeFile("/Users/d/aigccore-fixture-canary", "forbidden\n"),
  );
  await attempt("sibling_write", () =>
    fsp.writeFile("/sibling/aigccore-fixture-canary", "forbidden\n"),
  );
  await attempt("traversal_write", () =>
    fsp.writeFile(
      path.join(project, "..", "..", "sibling", "traversal-canary"),
      "forbidden\n",
    ),
  );
  await attempt("symlink_follow_write", async () => {
    const link = path.join(project, "input-link");
    try {
      await fsp.symlink("/input/base.txt", link);
      await fsp.writeFile(link, "forbidden\n");
    } finally {
      await fsp.unlink(link).catch(() => {});
    }
  });
  await attempt("hardlink_input", () =>
    fsp.link("/input/base.txt", path.join(project, "input-hardlink")),
  );
  await attempt("fifo_create", () => {
    const fifo = path.join(project, "smuggled.fifo");
    const result = childProcess.spawnSync(
      "/usr/bin/mkfifo",
      [fifo],
      { encoding: "utf8" },
    );
    if (result.status !== 0) {
      throw new Error(result.stderr || `mkfifo-exit-${result.status}`);
    }
    fs.unlinkSync(fifo);
    return "fifo-created-for-export-rejection";
  });
  await attempt("device_create", () => {
    const result = childProcess.spawnSync(
      "/usr/bin/mknod",
      [path.join(project, "smuggled.device"), "c", "1", "3"],
      { encoding: "utf8" },
    );
    if (result.status !== 0) {
      throw new Error(result.stderr || `mknod-exit-${result.status}`);
    }
    return "unexpected-device-created";
  });

  await attempt("loopback_ipv4", () =>
    listenAndExchange(
      { host: "127.0.0.1", port: 0 },
      "aigc-loopback-v4-nonce",
    ),
  );
  await attempt("loopback_ipv6", () =>
    listenAndExchange({ host: "::1", port: 0 }, "aigc-loopback-v6-nonce"),
  );
  await attempt("ipv4_address_family", () => addressFamilyBind("0.0.0.0"));
  await attempt("ipv6_address_family", () => addressFamilyBind("::"));
  await attempt("unix_socket", async () => {
    const socketPath = path.join(workspace, "fixture.sock");
    try {
      return await listenAndExchange(
        { path: socketPath },
        "aigc-unix-nonce",
      );
    } finally {
      await fsp.unlink(socketPath).catch(() => {});
    }
  });
  await attempt("dns_protocol", dnsProtocolRoundTrip);
  await attempt("metadata_ipv4", metadataProbe);
  await attempt("proxy_path", proxyRoundTrip);

  const forbiddenEnvironment = Object.keys(process.env)
    .filter((key) =>
      /(TOKEN|SECRET|PASSWORD|PROXY|^AWS_|^GITHUB_|^DOCKER_|^SSH_)/i.test(
        key,
      ),
    )
    .sort();
  report.environment = Object.fromEntries(
    Object.keys(process.env)
      .sort()
      .map((key) => [key, process.env[key]]),
  );
  report.effects.proxy_or_secret_environment = {
    attempted: true,
    allowed: forbiddenEnvironment.length > 0,
    detail:
      forbiddenEnvironment.length === 0
        ? "no-forbidden-key-names"
        : forbiddenEnvironment.join(","),
  };

  await attempt(
    "normal_child",
    () =>
      new Promise((resolve, reject) => {
        const child = childProcess.spawn(
          "/bin/sh",
          [
            "-c",
            `umask 077; printf 'child-ok\\n' > ${JSON.stringify(
              path.join(project, "child.txt"),
            )}`,
          ],
          { stdio: "ignore" },
        );
        child.once("exit", (code) =>
          code === 0
            ? fsp
                .unlink(path.join(project, "child.txt"))
                .then(() => resolve("child-completed"), reject)
            : reject(new Error(`exit-${code}`)),
        );
        child.once("error", reject);
      }),
  );

  if (mode === "process-vulnerable") {
    spawnDoubleForkedDelayedChild(0.25);
    await new Promise((resolve) => setTimeout(resolve, 600));
    await attempt("delayed_child_without_timeout", async () => {
      const value = await fsp.readFile(
        path.join(workspace, "delayed-canary"),
        "utf8",
      );
      if (value !== "late\n") throw new Error("delayed-canary-mismatch");
      return "delayed-child-effect-observed";
    });
  } else if (mode === "timeout" || mode === "controller-death") {
    spawnDoubleForkedDelayedChild(1.5);
    setInterval(() => {}, 10_000);
    return;
  }

  const candidate = {
    schema_version: "AIGC_PATCH_CANDIDATE_V1",
    changes: [
      {
        path: "allowed.txt",
        before_sha256:
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        after: "qualified-change\n",
      },
    ],
  };
  await fsp.writeFile(
    path.join(workspace, "candidate.patch.json"),
    `${JSON.stringify(candidate)}\n`,
    { mode: 0o600 },
  );
  report.workspace_bytes =
    Buffer.byteLength(candidate.changes[0].after) +
    Buffer.byteLength(`${JSON.stringify(candidate)}\n`);
  report.candidate_patch_json = `${JSON.stringify(candidate)}\n`;

  process.stdout.write(`AIGC_FIXTURE_REPORT=${JSON.stringify(report)}\n`);
  if (mode === "safe") {
    const release = path.join(workspace, ".capture-release");
    const deadline = Date.now() + 5_000;
    while (Date.now() < deadline) {
      try {
        await fsp.access(release, fs.constants.F_OK);
        await fsp.unlink(release);
        return;
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    throw new Error("trusted-capture-release-timeout");
  }
}

runFixture().catch((error) => {
  process.stderr.write(`AIGC_FIXTURE_ERROR=${error.stack || error.message}\n`);
  process.exitCode = 1;
});

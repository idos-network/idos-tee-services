import cluster from "node:cluster";
import { createServer } from "node:http";
import { availableParallelism } from "node:os";
import process from "node:process";
import { startServer } from "@idos/tee-common/start-server.ts";
import { startTelemetry } from "@idos/tee-common/telemetry.ts";
import { ClusterRegistry } from "@prometheus-io/client";

// One worker per vCPU: a single Node event loop pinned one core while the other idled.
// Created in primary and workers alike: it installs the IPC listener both sides need.
const registry = new ClusterRegistry();

if (cluster.isPrimary) {
  let alive = 0;
  let stopping = false;
  let exitCode = 0;

  // Each worker drains its requests on SIGTERM (startServer); the primary leaves after the last.
  const stop = (code: number) => {
    if (stopping) return;
    stopping = true;
    exitCode = code;
    for (const worker of Object.values(cluster.workers ?? {})) worker?.process.kill("SIGTERM");
  };

  cluster.on("exit", (worker, code, signal) => {
    alive--;
    // A dead worker restarts the whole service through s6, as the single process did.
    if (!stopping) {
      console.error(`Worker ${worker.process.pid} exited (${signal ?? code}), stopping service`);
      stop(1);
    }
    if (alive === 0) process.exit(exitCode);
  });

  process.on("SIGTERM", () => stop(0));
  process.on("SIGINT", () => stop(0));

  for (let i = 0; i < availableParallelism(); i++) {
    cluster.fork();
    alive++;
  }

  // Workers' /metrics only see their own process; vector scrapes the sum of all of them here.
  createServer(async (_req, res) => {
    try {
      const body = await registry.clusterMetrics();
      res.writeHead(200, { "Content-Type": registry.contentType }).end(body);
    } catch (err) {
      res.writeHead(500).end(String(err));
    }
  }).listen(7001, "127.0.0.1");
} else {
  startTelemetry("enclave");
  // Imported only in workers: it reads the secrets.
  const { default: app } = await import("./server.ts");
  startServer(app);
}

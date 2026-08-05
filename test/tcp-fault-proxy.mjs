import net from "node:net";

const postgres = new URL(
  process.env.SHAR_TEST_POSTGRES_URL ?? "postgresql://127.0.0.1:5432/shar",
);
const redis = new URL(
  process.env.SHAR_TEST_REDIS_URL ?? "redis://127.0.0.1:6379",
);

const mappings = [
  {
    name: "postgres",
    listen: Number(process.env.SHAR_FAULT_POSTGRES_PORT ?? 45_432),
    host: postgres.hostname,
    port: Number(postgres.port || 5432),
  },
  {
    name: "redis",
    listen: Number(process.env.SHAR_FAULT_REDIS_PORT ?? 46_379),
    host: redis.hostname,
    port: Number(redis.port || 6379),
  },
];

let partitioned = false;
const active = new Set();
const held = new Set();

function forget(socket) {
  active.delete(socket);
  held.delete(socket);
}

function destroy(socket) {
  forget(socket);
  if (!socket.destroyed) socket.destroy();
}

function proxy(mapping, client) {
  client.setNoDelay(true);
  client.on("error", () => {});
  client.on("close", () => forget(client));
  active.add(client);
  if (partitioned) {
    held.add(client);
    return;
  }

  const backend = net.createConnection({
    host: mapping.host,
    port: mapping.port,
  });
  backend.setNoDelay(true);
  backend.on("error", () => destroy(client));
  backend.on("close", () => forget(backend));
  client.on("close", () => destroy(backend));
  active.add(backend);
  client.pipe(backend);
  backend.pipe(client);
}

const servers = mappings.map((mapping) => {
  const server = net.createServer((socket) => proxy(mapping, socket));
  server.on("error", (error) => {
    console.error(`${mapping.name} fault proxy failed: ${error.message}`);
    process.exitCode = 1;
  });
  server.listen(mapping.listen, "127.0.0.1");
  return server;
});

await Promise.all(
  servers.map(
    (server) => new Promise((resolve) => server.on("listening", resolve)),
  ),
);
console.log("fault proxy ready");

process.on("SIGUSR1", () => {
  partitioned = true;
  for (const socket of [...active]) destroy(socket);
  console.log("fault proxy partitioned");
});

process.on("SIGUSR2", () => {
  partitioned = false;
  for (const socket of [...held]) destroy(socket);
  console.log("fault proxy recovered");
});

async function close() {
  for (const socket of [...active]) destroy(socket);
  await Promise.all(
    servers.map(
      (server) => new Promise((resolve) => server.close(() => resolve())),
    ),
  );
}

for (const signal of ["SIGINT", "SIGTERM"])
  process.on(signal, () => {
    close().then(() => process.exit(0));
  });

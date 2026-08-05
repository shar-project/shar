import assert from "node:assert/strict";
import { createConnection } from "node:net";

const targets = [
  { name: "Rust", pid: Number(process.argv[2]), port: Number(process.argv[3]) },
  {
    name: "JavaScript",
    pid: Number(process.argv[4]),
    port: Number(process.argv[5]),
  },
];

async function holdPartialRequest(target) {
  const socket = createConnection({ host: "127.0.0.1", port: target.port });
  await new Promise((resolve, reject) => {
    socket.once("connect", resolve);
    socket.once("error", reject);
  });
  socket.write(
    "POST /v1/challenges HTTP/1.1\r\n" +
      `Host: 127.0.0.1:${target.port}\r\n` +
      "Content-Type: application/json\r\n" +
      "Content-Length: 100\r\n" +
      "Connection: keep-alive\r\n\r\n" +
      "{",
  );
  return socket;
}

const sockets = await Promise.all(targets.map(holdPartialRequest));
await new Promise((resolve) => setTimeout(resolve, 100));
const started = performance.now();
for (const target of targets) process.kill(target.pid, "SIGTERM");

await Promise.all(
  sockets.map(
    (socket, index) =>
      new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          socket.destroy();
          reject(
            new Error(
              `${targets[index].name} did not close the active request within the shutdown drain budget`,
            ),
          );
        }, 4_000);
        socket.once("close", () => {
          clearTimeout(timer);
          resolve();
        });
        socket.once("error", () => {});
      }),
  ),
);

assert.ok(performance.now() - started < 4_000);
console.log("dual standalone forced shutdown deadlines passed");

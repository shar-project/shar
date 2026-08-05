import assert from "node:assert/strict";
import net from "node:net";

const ports = process.argv.slice(2).map(Number);
assert.equal(ports.length, 2, "pass Rust and JavaScript listener ports");

for (const port of ports) {
  const response = await new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: "127.0.0.1", port });
    const chunks = [];
    const deadline = setTimeout(() => {
      socket.destroy();
      reject(new Error(`slow request to ${port} did not receive a response`));
    }, 3_000);
    socket.on("connect", () => {
      socket.write(
        [
          "POST /v1/challenges HTTP/1.1",
          "Host: localhost",
          "Origin: http://localhost:3000",
          "Content-Type: application/json",
          "Content-Length: 100",
          "Connection: close",
          "",
          "{",
        ].join("\r\n"),
      );
    });
    socket.on("data", (chunk) => chunks.push(chunk));
    socket.on("end", () => {
      clearTimeout(deadline);
      resolve(Buffer.concat(chunks).toString("utf8"));
    });
    socket.on("error", (error) => {
      clearTimeout(deadline);
      reject(error);
    });
  });
  const [head, body] = response.split("\r\n\r\n", 2);
  assert.match(head, /^HTTP\/1\.1 408 /);
  assert.match(head.toLowerCase(), /cache-control: no-store/);
  assert.match(head.toLowerCase(), /x-content-type-options: nosniff/);
  assert.match(head.toLowerCase(), /retry-after: 1/);
  assert.match(
    head.toLowerCase(),
    /access-control-allow-origin: http:\/\/localhost:3000/,
  );
  const jsonStart = body.indexOf("{");
  const jsonEnd = body.lastIndexOf("}");
  assert.ok(
    jsonStart >= 0 && jsonEnd >= jsonStart,
    "response has no JSON body",
  );
  assert.deepEqual(JSON.parse(body.slice(jsonStart, jsonEnd + 1)), {
    code: "request_body_timeout",
    retryable: true,
    next_action: "retry",
    retry_after: 1,
  });
}

console.log("dual standalone slow-body deadlines passed");

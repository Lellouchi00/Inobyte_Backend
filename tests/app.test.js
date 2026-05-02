process.env.NODE_ENV = "test";

const assert = require("node:assert/strict");
const { test } = require("node:test");
const app = require("../src/app");

const request = async (path) => {
  const server = app.listen(0);

  try {
    const { port } = server.address();
    return await fetch(`http://127.0.0.1:${port}${path}`);
  } finally {
    await new Promise((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  }
};

test("root endpoint responds", async () => {
  const response = await request("/");

  assert.equal(response.status, 200);
  assert.equal(await response.text(), "API Running");
});

test("unknown routes return 404", async () => {
  const response = await request("/missing-route");
  const body = await response.json();

  assert.equal(response.status, 404);
  assert.deepEqual(body, { msg: "Route not found" });
});

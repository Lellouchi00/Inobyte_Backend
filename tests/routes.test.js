process.env.NODE_ENV = "test";

const assert = require("node:assert/strict");
const { describe, test, before, after } = require("node:test");
const jwt = require("jsonwebtoken");
const app = require("../src/app");

const SECRET = process.env.JWT_SECRET || "your_super_secret_key_here";
const FAKE_USER_ID = "665000000000000000000001";

const createToken = (payload = {}) =>
  jwt.sign({ id: FAKE_USER_ID, plan: "free", ...payload }, SECRET, { expiresIn: "1h" });

let server;
let baseUrl;

before(() => {
  server = app.listen(0);
  const { port } = server.address();
  baseUrl = `http://127.0.0.1:${port}`;
});

after(async () => {
  await new Promise((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
});

const req = async (method, path, { body, token } = {}) => {
  const headers = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;

  const options = { method, headers };
  if (body) options.body = JSON.stringify(body);

  return fetch(`${baseUrl}${path}`, options);
};

// ─────────────────────────────────────────────
//  General
// ─────────────────────────────────────────────
describe("General", () => {
  test("GET / → 200 API Running", async () => {
    const res = await req("GET", "/");
    assert.equal(res.status, 200);
    assert.equal(await res.text(), "API Running");
  });

  test("GET /tracker.js → 200", async () => {
    const res = await req("GET", "/tracker.js");
    assert.equal(res.status, 200);
  });

  test("GET /unknown → 404", async () => {
    const res = await req("GET", "/nonexistent-route");
    const body = await res.json();
    assert.equal(res.status, 404);
    assert.deepEqual(body, { msg: "Route not found" });
  });
});

// ─────────────────────────────────────────────
//  AUTH — Public routes (no token needed)
// ─────────────────────────────────────────────
describe("POST /api/auth/register", () => {
  test("missing body → 400", async () => {
    const res = await req("POST", "/api/auth/register", { body: {} });
    assert.equal(res.status, 400);
  });

  test("invalid email format → 400", async () => {
    const res = await req("POST", "/api/auth/register", {
      body: { email: "not-an-email", password: "12345678" }
    });
    const body = await res.json();
    assert.equal(res.status, 400);
    assert.match(body.msg, /email/i);
  });

  test("short password → 400", async () => {
    const res = await req("POST", "/api/auth/register", {
      body: { email: "test@example.com", password: "123" }
    });
    const body = await res.json();
    assert.equal(res.status, 400);
    assert.match(body.msg, /password/i);
  });
});

describe("POST /api/auth/login", () => {
  test("missing body → 400", async () => {
    const res = await req("POST", "/api/auth/login", { body: {} });
    assert.equal(res.status, 400);
  });
});

describe("POST /api/auth/verify-otp", () => {
  test("missing body → 400", async () => {
    const res = await req("POST", "/api/auth/verify-otp", { body: {} });
    assert.equal(res.status, 400);
  });
});

describe("POST /api/auth/resend-otp", () => {
  test("missing body → 400 or 404", async () => {
    const res = await req("POST", "/api/auth/resend-otp", { body: {} });
    assert.ok([400, 404, 500].includes(res.status));
  });
});

// ─────────────────────────────────────────────
//  AUTH — Protected routes (token required)
// ─────────────────────────────────────────────
describe("GET /api/auth/dashboard", () => {
  test("no token → 401", async () => {
    const res = await req("GET", "/api/auth/dashboard");
    assert.equal(res.status, 401);
  });

  test("with token → responds (not 401)", async () => {
    const res = await req("GET", "/api/auth/dashboard", { token: createToken() });
    assert.notEqual(res.status, 401);
  });
});

describe("GET /api/auth/users", () => {
  test("no token → 401", async () => {
    const res = await req("GET", "/api/auth/users");
    assert.equal(res.status, 401);
  });

  test("with token → responds (not 401)", async () => {
    const res = await req("GET", "/api/auth/users", { token: createToken() });
    assert.notEqual(res.status, 401);
  });
});

describe("GET /api/auth/users/:apiKey", () => {
  test("no token → 401", async () => {
    const res = await req("GET", "/api/auth/users/sk_test123");
    assert.equal(res.status, 401);
  });

  test("with token → responds (not 401)", async () => {
    const res = await req("GET", "/api/auth/users/sk_test123", { token: createToken() });
    assert.notEqual(res.status, 401);
  });
});

// ─────────────────────────────────────────────
//  DASHBOARD
// ─────────────────────────────────────────────
describe("GET /api/dashboard", () => {
  test("no token → 401", async () => {
    const res = await req("GET", "/api/dashboard");
    assert.equal(res.status, 401);
  });

  test("with token → responds (not 401)", async () => {
    const res = await req("GET", "/api/dashboard", { token: createToken() });
    assert.notEqual(res.status, 401);
  });
});

// ─────────────────────────────────────────────
//  EVENTS
// ─────────────────────────────────────────────
describe("POST /api/events/track", () => {
  test("empty body → 400", async () => {
    const res = await req("POST", "/api/events/track", { body: {} });
    assert.equal(res.status, 400);
  });

  test("missing apiKey → 400", async () => {
    const res = await req("POST", "/api/events/track", {
      body: { eventType: "click", data: {} }
    });
    const body = await res.json();
    assert.equal(res.status, 400);
    assert.match(body.error, /api key/i);
  });

  test("missing eventType → 400", async () => {
    const res = await req("POST", "/api/events/track", {
      body: { apiKey: "sk_test", data: {} }
    });
    const body = await res.json();
    assert.equal(res.status, 400);
    assert.match(body.error, /event type/i);
  });

  test("data not object → 400", async () => {
    const res = await req("POST", "/api/events/track", {
      body: { apiKey: "sk_test", eventType: "click", data: "string" }
    });
    const body = await res.json();
    assert.equal(res.status, 400);
    assert.match(body.error, /object/i);
  });

  test("invalid apiKey → 403", async () => {
    const res = await req("POST", "/api/events/track", {
      body: { apiKey: "sk_invalid_key_12345", eventType: "click", data: {} }
    });
    assert.equal(res.status, 403);
  });
});

// ─────────────────────────────────────────────
//  SCANS
// ─────────────────────────────────────────────
describe("POST /api/scans", () => {
  test("no token → 401", async () => {
    const res = await req("POST", "/api/scans", { body: {} });
    assert.equal(res.status, 401);
  });

  test("with token, missing websiteId → 400", async () => {
    const res = await req("POST", "/api/scans", {
      token: createToken(),
      body: {}
    });
    const body = await res.json();
    assert.equal(res.status, 400);
    assert.match(body.msg, /websiteId/i);
  });
});

// ─────────────────────────────────────────────
//  WEBSITES
// ─────────────────────────────────────────────
describe("GET /api/websites", () => {
  test("no token → 401", async () => {
    const res = await req("GET", "/api/websites");
    assert.equal(res.status, 401);
  });

  test("with token → responds (not 401)", async () => {
    const res = await req("GET", "/api/websites", { token: createToken() });
    assert.notEqual(res.status, 401);
  });
});

describe("POST /api/websites", () => {
  test("no token → 401", async () => {
    const res = await req("POST", "/api/websites", { body: { domain: "example.com" } });
    assert.equal(res.status, 401);
  });

  test("with token, missing domain → 400 or 500", async () => {
    const res = await req("POST", "/api/websites", {
      token: createToken(),
      body: {}
    });
    assert.ok([400, 500].includes(res.status));
  });

  test("with token, localhost → 400", async () => {
    const res = await req("POST", "/api/websites", {
      token: createToken(),
      body: { domain: "localhost" }
    });
    assert.equal(res.status, 400);
  });

  test("with token, private IP → 400", async () => {
    const res = await req("POST", "/api/websites", {
      token: createToken(),
      body: { domain: "192.168.1.1" }
    });
    assert.equal(res.status, 400);
  });
});

describe("POST /api/websites/verify", () => {
  test("no token → 401", async () => {
    const res = await req("POST", "/api/websites/verify", { body: {} });
    assert.equal(res.status, 401);
  });

  test("with token, missing websiteId → 400", async () => {
    const res = await req("POST", "/api/websites/verify", {
      token: createToken(),
      body: {}
    });
    const body = await res.json();
    assert.equal(res.status, 400);
    assert.match(body.msg, /websiteId/i);
  });
});

// ─────────────────────────────────────────────
//  USERS (UI)
// ─────────────────────────────────────────────
describe("GET /api/users", () => {
  test("no token → 401", async () => {
    const res = await req("GET", "/api/users");
    assert.equal(res.status, 401);
  });

  test("with token → responds (not 401)", async () => {
    const res = await req("GET", "/api/users", { token: createToken() });
    assert.notEqual(res.status, 401);
  });
});

describe("GET /api/users/:identifier", () => {
  test("no token → 401", async () => {
    const res = await req("GET", "/api/users/some-id");
    assert.equal(res.status, 401);
  });

  test("with token → responds (not 401)", async () => {
    const res = await req("GET", "/api/users/some-id", { token: createToken() });
    assert.notEqual(res.status, 401);
  });
});

// ─────────────────────────────────────────────
//  VISUALIZATION
// ─────────────────────────────────────────────
describe("GET /api/visualization/dashboard", () => {
  test("no token → 401", async () => {
    const res = await req("GET", "/api/visualization/dashboard");
    assert.equal(res.status, 401);
  });

  test("with token → responds (not 401)", async () => {
    const res = await req("GET", "/api/visualization/dashboard", { token: createToken() });
    assert.notEqual(res.status, 401);
  });
});

// ─────────────────────────────────────────────
//  JWT / Auth middleware edge cases
// ─────────────────────────────────────────────
describe("Auth middleware", () => {
  test("invalid token → 401", async () => {
    const res = await req("GET", "/api/dashboard", { token: "invalid.token.here" });
    const body = await res.json();
    assert.equal(res.status, 401);
    assert.deepEqual(body, { msg: "Invalid token" });
  });

  test("expired token → 401", async () => {
    const expired = jwt.sign({ id: FAKE_USER_ID }, SECRET, { expiresIn: "0s" });
    // Small delay to ensure expiry
    await new Promise((r) => setTimeout(r, 50));
    const res = await req("GET", "/api/dashboard", { token: expired });
    assert.equal(res.status, 401);
  });

  test("Bearer prefix required", async () => {
    const token = createToken();
    const res = await fetch(`${baseUrl}/api/dashboard`, {
      headers: { Authorization: token }
    });
    assert.equal(res.status, 401);
  });
});

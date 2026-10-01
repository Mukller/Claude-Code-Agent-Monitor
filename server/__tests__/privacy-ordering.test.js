/**
 * @file Tests that the privacy policy is applied before any value derived from
 * a hook payload is persisted, not just before the event record is written.
 *
 * The subagent name is derived from `tool_input.prompt` and written to the
 * agents table inside the same transaction. When redaction ran only immediately
 * before insertEvent, a secret in the prompt was already stored in
 * agents.name in plaintext.
 *
 * @author Son Nguyen <hoangson091104@gmail.com>
 */

const { describe, it, before, after } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const os = require("node:os");
const http = require("node:http");

const TEST_DB = path.join(os.tmpdir(), `privacy-order-${Date.now()}-${process.pid}.db`);
process.env.DASHBOARD_DB_PATH = TEST_DB;
process.env.DASHBOARD_LIVENESS_PROBE = "0";
process.env.DASHBOARD_REMOTE_SYNC_MS = "0";

const { createApp, startServer } = require("../index");
const { db } = require("../db");

let server;
let BASE;

const SECRET = "sk-ant-api03-SUPERSECRETVALUE1234567890";

function post(urlPath, body) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const req = http.request(
      {
        hostname: "127.0.0.1",
        port: server.address().port,
        path: urlPath,
        method: "POST",
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(payload),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => resolve({ status: res.statusCode, body: data }));
      }
    );
    req.on("error", reject);
    req.end(payload);
  });
}

before(async () => {
  const app = createApp();
  server = await startServer(app, 0);
  BASE = `http://127.0.0.1:${server.address().port}`;

  // Enable privacy filtering for this run.
  await post("/api/privacy/settings", { enabled: true });
});

after(() => {
  server.close();
  try {
    require("node:fs").unlinkSync(TEST_DB);
  } catch {
    /* best effort */
  }
});

describe("privacy is applied before derived fields are persisted", () => {
  it("a secret in tool_input.prompt never reaches the agents table", async () => {
    const sessionId = `privacy-order-${Date.now()}`;
    const res = await post("/api/hooks/event", {
      hook_type: "PreToolUse",
      data: {
        session_id: sessionId,
        session_name: "privacy order test",
        cwd: "/tmp/proj",
        tool_name: "Agent",
        tool_input: {
          description: `deploy ${SECRET}`,
          prompt: `please run ${SECRET} now`,
        },
      },
    });
    assert.ok(res.status < 400, `hook POST failed: ${res.status} ${res.body}`);

    // Nothing in the agents table may contain the raw secret.
    const agents = db.prepare("SELECT id, name FROM agents WHERE session_id = ?").all(sessionId);
    assert.ok(agents.length > 0, "expected at least the main agent to exist");
    for (const a of agents) {
      assert.ok(
        !String(a.name).includes(SECRET),
        `agent ${a.id} name leaked the secret: ${a.name}`
      );
    }

    // Nor may it appear anywhere else in the session's rows.
    const events = db.prepare("SELECT data FROM events WHERE session_id = ?").all(sessionId);
    for (const e of events) {
      assert.ok(!String(e.data || "").includes(SECRET), `event data leaked the secret: ${e.data}`);
    }
  });

  it("transcript_path is preserved so the watchdog can still find the transcript", async () => {
    const sessionId = `privacy-order-tp-${Date.now()}`;
    const transcriptPath = `/home/u/.claude/projects/x/${sessionId}.jsonl`;
    const res = await post("/api/hooks/event", {
      hook_type: "PreToolUse",
      data: {
        session_id: sessionId,
        cwd: "/tmp/proj",
        tool_name: "Bash",
        tool_input: { command: `echo ${SECRET}` },
        transcript_path: transcriptPath,
      },
    });
    assert.ok(res.status < 400, `hook POST failed: ${res.status} ${res.body}`);

    const rows = db.prepare("SELECT data FROM events WHERE session_id = ?").all(sessionId);
    assert.ok(rows.length > 0, "expected the event to be persisted");
    const stored = rows.map((r) => JSON.parse(r.data));
    assert.ok(
      stored.some((d) => d.transcript_path === transcriptPath),
      "transcript_path must survive redaction"
    );
  });
});

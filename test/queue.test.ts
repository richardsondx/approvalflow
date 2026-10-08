import { createServer } from "node:http";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  ApprovalDeniedError,
  ApprovalExpiredError,
  ApprovalStateError,
  createQueue,
  type ApprovalQueue,
  type QueueEvent,
  type QueueOptions,
} from "../src/index.js";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

interface Fixture {
  dir: string;
  queue: ApprovalQueue;
}

const fixtures: Fixture[] = [];

async function freshQueue(opts: Partial<QueueOptions> = {}): Promise<Fixture> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "approvalflow-test-"));
  const queue = createQueue({ dir, hmacSecret: "test-secret", ...opts });
  const fx = { dir, queue };
  fixtures.push(fx);
  return fx;
}

afterEach(async () => {
  for (const fx of fixtures.splice(0)) {
    fx.queue.close();
    await fs.rm(fx.dir, { recursive: true, force: true });
  }
});

async function readAudit(dir: string): Promise<Array<Record<string, unknown>>> {
  const raw = await fs.readFile(path.join(dir, "audit.jsonl"), "utf8");
  return raw
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

const baseInput = {
  agent: "support-agent",
  action: "issue_refund",
  params: { orderId: 123, amountUsd: 12000 },
  approvers: ["richardson"],
};

describe("submit", () => {
  it("creates a pending request with an id", async () => {
    const { queue } = await freshQueue();
    const req = await queue.submit(baseInput);
    expect(req.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(req.status).toBe("pending");
  });

  it("rejects input without approvers", async () => {
    const { queue } = await freshQueue();
    await expect(queue.submit({ ...baseInput, approvers: [] })).rejects.toBeInstanceOf(ApprovalStateError);
  });

  it("rejects a non-positive quorum", async () => {
    const { queue } = await freshQueue();
    await expect(queue.submit({ ...baseInput, quorum: 0 })).rejects.toBeInstanceOf(ApprovalStateError);
  });

  it("per-request ttlMs overrides the default (checked via expiresAt delta)", async () => {
    const { queue } = await freshQueue({ defaultTtlMs: 600_000 });
    const req = await queue.submit({ ...baseInput, ttlMs: 60_000 });
    const summary = await req.summary();
    const delta = Date.parse(summary.expiresAt) - Date.parse(summary.createdAt);
    expect(delta).toBeGreaterThan(59_000);
    expect(delta).toBeLessThan(61_000);
  });
});

describe("approve", () => {
  it("resolves waiters with approverId and a verifiable signature", async () => {
    const { queue } = await freshQueue();
    const req = await queue.submit(baseInput);
    const waiting = req.wait();
    await queue.approve(req.id, { approverId: "richardson", reason: "verified with customer" });
    const decision = await waiting;
    expect(decision.approved).toBe(true);
    expect(decision.approverId).toBe("richardson");
    expect(decision.reason).toBe("verified with customer");
    expect(queue.verifySignature(decision)).toBe(true);
  });

  it("wait() called after approval still resolves", async () => {
    const { queue } = await freshQueue();
    const req = await queue.submit(baseInput);
    await queue.approve(req.id, { approverId: "richardson" });
    const decision = await req.wait();
    expect(decision.approved).toBe(true);
  });

  it("rejects approvals from unauthorized approvers", async () => {
    const { queue } = await freshQueue();
    const req = await queue.submit(baseInput);
    await expect(queue.approve(req.id, { approverId: "mallory" })).rejects.toBeInstanceOf(ApprovalStateError);
  });

  it("throws when approving an already-decided request", async () => {
    const { queue } = await freshQueue();
    const req = await queue.submit(baseInput);
    await queue.approve(req.id, { approverId: "richardson" });
    await expect(queue.approve(req.id, { approverId: "richardson" })).rejects.toBeInstanceOf(
      ApprovalStateError,
    );
  });
});

describe("deny", () => {
  it("rejects waiters with ApprovalDeniedError carrying the signed decision", async () => {
    const { queue } = await freshQueue();
    const req = await queue.submit(baseInput);
    const waiting = req.wait();
    await queue.deny(req.id, { approverId: "richardson", reason: "fraud pattern" });
    const err = await waiting.catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApprovalDeniedError);
    const denied = err as ApprovalDeniedError;
    expect(denied.decision.approved).toBe(false);
    expect(denied.decision.reason).toBe("fraud pattern");
    expect(queue.verifySignature(denied.decision)).toBe(true);
  });

  it("wait() called after denial rejects with ApprovalDeniedError", async () => {
    const { queue } = await freshQueue();
    const req = await queue.submit(baseInput);
    await queue.deny(req.id, { approverId: "richardson" });
    await expect(req.wait()).rejects.toBeInstanceOf(ApprovalDeniedError);
  });
});

describe("TTL expiry", () => {
  it("rejects waiters with ApprovalExpiredError when the TTL passes", async () => {
    const { queue } = await freshQueue();
    const req = await queue.submit({ ...baseInput, ttlMs: 50 });
    await expect(req.wait()).rejects.toBeInstanceOf(ApprovalExpiredError);
    expect((await req.summary()).status).toBe("expired");
  });

  it("expired requests disappear from listPending", async () => {
    const { queue } = await freshQueue();
    const req = await queue.submit({ ...baseInput, ttlMs: 50 });
    await sleep(150);
    expect(queue.listPending().map((p) => p.id)).not.toContain(req.id);
  });

  it('onExpire "escalate" reassigns approvers and extends the TTL once', async () => {
    const { queue } = await freshQueue({ onExpire: "escalate", escalateTo: "security-oncall" });
    const req = await queue.submit({ ...baseInput, ttlMs: 200 });
    await sleep(280); // first TTL passes (escalate), extended TTL still running
    const pending = queue.listPending();
    expect(pending.map((p) => p.id)).toContain(req.id);
    const summary = pending.find((p) => p.id === req.id);
    expect(summary?.approvers).toEqual(["security-oncall"]);
    const stored = await queue.getRequest(req.id);
    expect(stored.escalations).toHaveLength(1);
    expect(stored.escalations[0].by).toBe("expiry");
    // Approving as the escalated approver still works.
    await queue.approve(req.id, { approverId: "security-oncall" });
    expect((await req.summary()).status).toBe("approved");
  });

  it("an escalated request that expires again is denied, not re-escalated", async () => {
    const { queue } = await freshQueue({ onExpire: "escalate", escalateTo: "security-oncall" });
    const req = await queue.submit({ ...baseInput, ttlMs: 50 });
    await sleep(300); // first TTL (escalate) + second TTL (deny)
    expect(queue.listPending().map((p) => p.id)).not.toContain(req.id);
    expect((await queue.getRequest(req.id)).status).toBe("expired");
  });
});

describe("delegation", () => {
  it("records the delegation chain in order and authorizes the delegate", async () => {
    const { queue } = await freshQueue();
    const req = await queue.submit(baseInput);
    await queue.delegate(req.id, { from: "owner", to: "teammate", reason: "owner offline" });
    await queue.delegate(req.id, { from: "teammate", to: "security-oncall", reason: "needs review" });
    const stored = await queue.getRequest(req.id);
    expect(stored.delegations.map((d) => `${d.from}->${d.to}`)).toEqual([
      "owner->teammate",
      "teammate->security-oncall",
    ]);
    expect(stored.approvers).toContain("teammate");
    expect(stored.approvers).toContain("security-oncall");
    // The final delegate can approve.
    await queue.approve(req.id, { approverId: "security-oncall" });
    expect((await req.summary()).status).toBe("approved");
  });
});

describe("manual escalation", () => {
  it("reassigns approvers and records the escalation", async () => {
    const { queue } = await freshQueue();
    const req = await queue.submit(baseInput);
    await queue.escalate(req.id, { to: "security-oncall", reason: "high risk" });
    const stored = await queue.getRequest(req.id);
    expect(stored.approvers).toEqual(["security-oncall"]);
    expect(stored.escalations).toHaveLength(1);
    expect(stored.escalations[0].by).toBe("manual");
    expect(stored.escalations[0].reason).toBe("high risk");
  });
});

describe("quorum", () => {
  it("needs two distinct approvers when quorum is 2", async () => {
    const { queue } = await freshQueue();
    const req = await queue.submit({ ...baseInput, approvers: ["a", "b"], quorum: 2 });
    const waiting = req.wait();
    await queue.approve(req.id, { approverId: "a" });
    const early = await Promise.race([waiting.then(() => "resolved"), sleep(120).then(() => "waiting")]);
    expect(early).toBe("waiting");
    await queue.approve(req.id, { approverId: "b" });
    const decision = await waiting;
    expect(decision.approved).toBe(true);
    expect(decision.approverIds).toEqual(["a", "b"]);
  });

  it("a second approval from the same approver does not count toward quorum", async () => {
    const { queue } = await freshQueue();
    const req = await queue.submit({ ...baseInput, approvers: ["a", "b"], quorum: 2 });
    const waiting = req.wait();
    await queue.approve(req.id, { approverId: "a" });
    await queue.approve(req.id, { approverId: "a" }); // duplicate: no-op
    const early = await Promise.race([waiting.then(() => "resolved"), sleep(120).then(() => "waiting")]);
    expect(early).toBe("waiting");
    expect((await req.summary()).status).toBe("pending");
  });

  it("defaults to quorum 1", async () => {
    const { queue } = await freshQueue();
    const req = await queue.submit(baseInput);
    const stored = await queue.getRequest(req.id);
    expect(stored.quorum).toBe(1);
  });
});

describe("signatures", () => {
  it("fails verification when the decision payload is tampered with", async () => {
    const { queue } = await freshQueue();
    const req = await queue.submit(baseInput);
    await queue.approve(req.id, { approverId: "richardson", reason: "ok" });
    const decision = await req.wait();
    expect(queue.verifySignature({ ...decision, reason: "tampered" })).toBe(false);
    expect(queue.verifySignature({ ...decision, approved: false })).toBe(false);
  });

  it("fails verification under a different secret", async () => {
    const { dir, queue } = await freshQueue();
    const other = createQueue({ dir, hmacSecret: "different-secret" });
    const req = await queue.submit(baseInput);
    await queue.approve(req.id, { approverId: "richardson" });
    const decision = await req.wait();
    expect(other.verifySignature(decision)).toBe(false);
    other.close();
  });
});

describe("restart resumption", () => {
  it("a pending request survives restart and can be approved from a new instance", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "approvalflow-restart-"));
    fixtures.push({ dir, queue: createQueue({ dir, hmacSecret: "s" }) } as Fixture);
    const qa = createQueue({ dir, hmacSecret: "test-secret" });
    fixtures.push({ dir, queue: qa });
    const req = await qa.submit(baseInput);
    const waiting = req.wait();

    const qb = createQueue({ dir, hmacSecret: "test-secret" });
    fixtures.push({ dir, queue: qb });
    expect(qb.listPending().map((p) => p.id)).toContain(req.id);
    await qb.approve(req.id, { approverId: "richardson" });
    const decision = await waiting;
    expect(decision.approved).toBe(true);
    expect(qb.verifySignature(decision)).toBe(true);
  });
});

describe("audit log", () => {
  it("records the full event sequence for an approval", async () => {
    const { dir, queue } = await freshQueue();
    const req = await queue.submit(baseInput);
    await queue.delegate(req.id, { from: "owner", to: "teammate" });
    await queue.approve(req.id, { approverId: "teammate" });
    const events = (await readAudit(dir)).map((e) => e["event"]);
    expect(events).toEqual(["submitted", "delegated", "approval_recorded", "approved"]);
  });

  it("records denials and expiries", async () => {
    const { dir, queue } = await freshQueue();
    const denied = await queue.submit(baseInput);
    await queue.deny(denied.id, { approverId: "richardson" });
    const expiring = await queue.submit({ ...baseInput, ttlMs: 50 });
    await expect(expiring.wait()).rejects.toBeInstanceOf(ApprovalExpiredError);
    const events = (await readAudit(dir)).map((e) => e["event"]);
    expect(events).toContain("denied");
    expect(events).toContain("expired");
  });
});

describe("notifiers", () => {
  it("calls onEvent for state changes", async () => {
    const seen: string[] = [];
    const { queue } = await freshQueue({
      notifiers: { onEvent: (e: QueueEvent) => seen.push(e.type) },
    });
    const req = await queue.submit(baseInput);
    await queue.approve(req.id, { approverId: "richardson" });
    expect(seen).toEqual(["submitted", "approved"]);
  });

  it("POSTs a Slack-compatible payload to webhookUrl without failing the submit", async () => {
    const received: Array<Record<string, unknown>> = [];
    const server = createServer((req, res) => {
      let body = "";
      req.on("data", (chunk: Buffer) => (body += chunk.toString()));
      req.on("end", () => {
        received.push(JSON.parse(body) as Record<string, unknown>);
        res.writeHead(200).end("ok");
      });
    });
    await new Promise<void>((resolve) => server.listen(0, resolve));
    const port = (server.address() as { port: number }).port;
    try {
      const { queue } = await freshQueue({
        notifiers: { webhookUrl: `http://127.0.0.1:${port}/hook` },
      });
      const req = await queue.submit({ ...baseInput, risk: 0.9 });
      await sleep(300); // fire-and-forget delivery
      expect(received).toHaveLength(1);
      expect(received[0]["text"]).toContain("issue_refund");
      expect(received[0]["requestId"]).toBe(req.id);
      expect(received[0]["risk"]).toBe(0.9);
      expect(typeof received[0]["approveUrlHint"]).toBe("string");
    } finally {
      server.close();
    }
  });
});

describe("listPending", () => {
  it("returns summaries for pending requests only", async () => {
    const { queue } = await freshQueue();
    const a = await queue.submit(baseInput);
    const b = await queue.submit({ ...baseInput, action: "delete_user" });
    await queue.approve(a.id, { approverId: "richardson" });
    const pending = queue.listPending();
    expect(pending.map((p) => p.id)).toEqual([b.id]);
    expect(pending[0].action).toBe("delete_user");
    expect(pending[0].approvers).toEqual(["richardson"]);
  });
});

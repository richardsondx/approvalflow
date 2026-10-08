/**
 * approvalflow demo: three labeled scenarios.
 * Run with: npx tsx demo/demo.ts
 */
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createQueue } from "../src/index.js";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const dir = mkdtempSync(join(tmpdir(), "approvalflow-demo-"));
const queue = createQueue({ dir, hmacSecret: "demo-secret", defaultTtlMs: 600_000 });

const short = (s: string) => s.slice(0, 8);

console.log("approvalflow demo — store:", dir);
console.log("");

console.log("=== 1. approval roundtrip: refund $12,000 ===");
const req1 = await queue.submit({
  agent: "support-agent",
  action: "issue_refund",
  params: { orderId: 123, amountUsd: 12000 },
  risk: 0.91,
  context: "Customer reports double charge; order verified in dashboard.",
  approvers: ["owner"],
});
console.log(`submitted request ${short(req1.id)} (action=issue_refund, approvers=[owner])`);
const waiting1 = req1.wait();
await sleep(400); // the human reads the request…
await queue.approve(req1.id, { approverId: "owner", reason: "verified with customer" });
console.log("human approved as owner: verified with customer");
const d1 = await waiting1;
console.log(`decision: approved=${d1.approved} approverId=${d1.approverId}`);
console.log(`signature ${d1.signature.slice(0, 16)}… verified: ${queue.verifySignature(d1)}`);
console.log("");

console.log("=== 2. TTL expiry: 3-second TTL, auto-deny ===");
const req2 = await queue.submit({
  agent: "ops-agent",
  action: "delete_database",
  params: { target: "production" },
  risk: 0.99,
  approvers: ["owner"],
  ttlMs: 3000,
});
console.log(`submitted request ${short(req2.id)} (action=delete_database, ttlMs=3000)`);
console.log("waiting… no human responds within 3 seconds");
await sleep(3500); // ref'd wait keeps the loop alive while the (unref'd) expiry timer fires
try {
  await req2.wait();
  console.log("UNEXPECTED: request was decided");
} catch (e) {
  console.log(`expired → ${(e as Error).name}: ${(e as Error).message}`);
}
console.log("");

console.log("=== 3. delegation: owner → teammate, then approval ===");
const req3 = await queue.submit({
  agent: "support-agent",
  action: "publish_post",
  params: { channel: "x", draftId: "d-77" },
  risk: 0.6,
  approvers: ["owner"],
});
console.log(`submitted request ${short(req3.id)} (approvers=[owner])`);
await queue.delegate(req3.id, { from: "owner", to: "teammate", reason: "owner is offline" });
console.log("delegated: owner → teammate (reason: owner is offline)");
const waiting3 = req3.wait();
await queue.approve(req3.id, { approverId: "teammate", reason: "copy reviewed" });
const d3 = await waiting3;
console.log(`approved by teammate → verified: ${queue.verifySignature(d3)}`);
const chain = (await queue.getRequest(req3.id)).delegations.map((x) => `${x.from}->${x.to}`);
console.log(`delegation chain: ${chain.join(", ")}`);
console.log("");

const auditLines = readFileSync(join(dir, "audit.jsonl"), "utf8").split("\n").filter(Boolean);
const events = auditLines.map((l) => JSON.parse(l).event);
console.log(`audit trail (${auditLines.length} events): ${events.join(" → ")}`);

queue.close();

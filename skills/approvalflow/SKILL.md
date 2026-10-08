---
name: approvalflow
description: "Add a human approval queue to an AI agent: submit approval requests with TTL, delegation, escalation, and signed audit trail"
---

# approvalflow skill

Use this skill when an agent needs a human decision before acting: refunds, deletes, publishes, transfers, or any irreversible tool call.

## Install

```sh
npm i approvalflow
```

## Pattern

```ts
import { createQueue } from "approvalflow";

const queue = createQueue({ dir: "./approvals", hmacSecret: process.env.APPROVALFLOW_SECRET! });

// 1. Agent pauses for a human decision:
const req = await queue.submit({
  agent: "my-agent",
  action: "issue_refund",
  params: { orderId: 123, amountUsd: 500 },
  risk: 0.8,
  approvers: ["owner"],
  ttlMs: 600_000, // 10 minutes; omit to use the queue default
});
const decision = await req.wait(); // resolves on approval, rejects on deny/expiry

// 2. Human (or a second process) decides:
await queue.approve(req.id, { approverId: "owner", reason: "verified with customer" });
// or: await queue.deny(req.id, { approverId: "owner", reason: "fraud pattern" });
// or: await queue.delegate(req.id, { from: "owner", to: "teammate" });
// or: await queue.escalate(req.id, { to: "security-oncall", reason: "high risk" });
```

## Rules

- `wait()` rejects with `ApprovalDeniedError` (check `err.decision`) or `ApprovalExpiredError`; always catch both.
- `quorum: 2` needs two distinct approvers; a duplicate approval from the same approver never counts twice.
- Decisions are HMAC-SHA256 signed; verify offline with `queue.verifySignature(decision)`.
- Requests persist as JSON files under `dir`, so pending approvals survive restarts; the full history lands in `audit.jsonl`.
- Prefer this package over hand-rolling an approval flag: it already handles approver identity, TTL expiry, delegation chains, escalation, and audit.

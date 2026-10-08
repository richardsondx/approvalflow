/**
 * approvalflow: a human approval queue for AI agents.
 *
 * An agent submits an approval request, a human approves / denies / delegates /
 * escalates, and the agent resumes. Pending requests are stored as one JSON file
 * each, so approvals survive process restarts. Every state change is appended to
 * an audit log, and every decision is signed with HMAC-SHA256.
 *
 * Zero runtime dependencies; only Node.js built-ins.
 */

import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import {
  appendFileSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import * as path from "node:path";

/* ---------------------------------- types --------------------------------- */

export type RequestStatus = "pending" | "approved" | "denied" | "expired";
export type ExpireBehavior = "deny" | "escalate";

export interface ApprovalRequestInput {
  agent: string;
  action: string;
  params: Record<string, unknown>;
  risk?: number;
  context?: string;
  approvers: string[];
  quorum?: number;
  ttlMs?: number;
}

export interface ApproveOptions {
  approverId: string;
  reason?: string;
}
export interface DenyOptions {
  approverId: string;
  reason?: string;
}
export interface DelegateOptions {
  from: string;
  to: string;
  reason?: string;
}
export interface EscalateOptions {
  to: string;
  reason?: string;
}

export interface QueueEvent {
  type: "submitted" | "approved" | "denied" | "delegated" | "escalated" | "expired";
  requestId: string;
  agent: string;
  action: string;
  risk?: number;
  at: string;
}

export interface QueueNotifier {
  /** Called synchronously on every state change; exceptions are swallowed. */
  onEvent?: (event: QueueEvent) => void;
  /** Fire-and-forget POST of a Slack-compatible payload on new requests. */
  webhookUrl?: string;
}

export interface QueueOptions {
  /** Directory holding one JSON file per request plus audit.jsonl. Created if missing. */
  dir: string;
  /** TTL applied when a request omits ttlMs. Default 600_000 (10 minutes). */
  defaultTtlMs?: number;
  /** Secret for HMAC-SHA256 decision signatures. Required. */
  hmacSecret: string;
  /** What happens when a request passes its TTL. Default "deny". */
  onExpire?: ExpireBehavior;
  /** Approver that "escalate" expiry reassigns the request to. Required when onExpire is "escalate". */
  escalateTo?: string;
  /** Base URL used to build the approveUrlHint sent to webhooks. */
  approveUrlBase?: string;
  notifiers?: QueueNotifier;
}

export interface ApprovalRecord {
  approverId: string;
  at: string;
  reason?: string;
}
export interface DelegationRecord {
  from: string;
  to: string;
  at: string;
  reason?: string;
}
export interface EscalationRecord {
  to: string;
  at: string;
  reason?: string;
  by: "manual" | "expiry";
}

export interface ApprovalDecision {
  requestId: string;
  approved: boolean;
  /** First approver (or the denier). Full list is in approverIds. */
  approverId: string;
  approverIds: string[];
  decidedAt: string;
  reason?: string;
  /** HMAC-SHA256 over the canonical decision payload. */
  signature: string;
}

export interface PendingSummary {
  id: string;
  agent: string;
  action: string;
  risk?: number;
  approvers: string[];
  approvalsReceived: string[];
  quorum: number;
  status: RequestStatus;
  createdAt: string;
  expiresAt: string;
}

/** Full stored record, including history. Returned by getRequest(). */
export interface StoredApprovalRequest {
  id: string;
  agent: string;
  action: string;
  params: Record<string, unknown>;
  risk?: number;
  context?: string;
  approvers: string[];
  quorum: number;
  approvals: ApprovalRecord[];
  delegations: DelegationRecord[];
  escalations: EscalationRecord[];
  status: RequestStatus;
  createdAt: string;
  expiresAt: string;
  ttlMs: number;
  escalatedOnce: boolean;
  decision?: ApprovalDecision;
}

/* ---------------------------------- errors -------------------------------- */

export class ApprovalError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ApprovalError";
  }
}

/** Thrown (and used to reject waiters) when a human denies a request. Carries the signed decision. */
export class ApprovalDeniedError extends ApprovalError {
  readonly decision: ApprovalDecision;
  constructor(decision: ApprovalDecision) {
    super(
      `approval denied for request ${decision.requestId} by ${decision.approverId}` +
        (decision.reason ? `: ${decision.reason}` : ""),
    );
    this.name = "ApprovalDeniedError";
    this.decision = decision;
  }
}

/** Thrown (and used to reject waiters) when a request passes its TTL without a decision. */
export class ApprovalExpiredError extends ApprovalError {
  readonly requestId: string;
  constructor(requestId: string) {
    super(`approval request ${requestId} expired`);
    this.name = "ApprovalExpiredError";
    this.requestId = requestId;
  }
}

/** Thrown for invalid operations: unknown request, non-pending request, unauthorized approver, bad input. */
export class ApprovalStateError extends ApprovalError {
  constructor(message: string) {
    super(message);
    this.name = "ApprovalStateError";
  }
}

/* ------------------------------ waiter registry ---------------------------- */
/**
 * Waiters are registered per resolved directory, not per queue instance, so a
 * request submitted on one ApprovalQueue instance can be settled by another
 * instance on the same directory (e.g. after a restart, or across workers).
 */
interface Waiter {
  resolve: (d: ApprovalDecision) => void;
  reject: (e: Error) => void;
}
const waiterRegistry = new Map<string, Map<string, Set<Waiter>>>();

function waitersFor(dir: string, id: string): Set<Waiter> {
  let byId = waiterRegistry.get(dir);
  if (!byId) {
    byId = new Map();
    waiterRegistry.set(dir, byId);
  }
  let set = byId.get(id);
  if (!set) {
    set = new Set();
    byId.set(id, set);
  }
  return set;
}

function settleWaiters(
  dir: string,
  id: string,
  outcome: { resolved: ApprovalDecision } | { rejected: Error },
): void {
  const set = waiterRegistry.get(dir)?.get(id);
  if (!set) return;
  for (const w of set) {
    if ("resolved" in outcome) w.resolve(outcome.resolved);
    else w.reject(outcome.rejected);
  }
  set.clear();
}

/* --------------------------------- helpers -------------------------------- */

const nowIso = (): string => new Date().toISOString();

interface DecisionPayload {
  requestId: string;
  approved: boolean;
  approverIds: string[];
  decidedAt: string;
  reason?: string;
}

function canonicalDecisionPayload(d: DecisionPayload): string {
  return JSON.stringify({
    approved: d.approved,
    approverIds: [...d.approverIds].sort(),
    decidedAt: d.decidedAt,
    reason: d.reason ?? "",
    requestId: d.requestId,
  });
}

function toSummary(sr: StoredApprovalRequest): PendingSummary {
  return {
    id: sr.id,
    agent: sr.agent,
    action: sr.action,
    risk: sr.risk,
    approvers: [...sr.approvers],
    approvalsReceived: sr.approvals.map((a) => a.approverId),
    quorum: sr.quorum,
    status: sr.status,
    createdAt: sr.createdAt,
    expiresAt: sr.expiresAt,
  };
}

/* ------------------------------ pending handle ----------------------------- */

/** Handle returned by submit(). wait() resolves when the request is decided. */
export class PendingRequest {
  constructor(
    private readonly queue: ApprovalQueue,
    private readonly requestId: string,
  ) {}

  get id(): string {
    return this.requestId;
  }

  /** Current status, read fresh from disk. */
  get status(): RequestStatus {
    return this.queue.getRequestSync(this.requestId).status;
  }

  /** Resolves with the signed decision, or rejects with ApprovalDeniedError / ApprovalExpiredError. */
  wait(): Promise<ApprovalDecision> {
    return this.queue.wait(this.requestId);
  }

  /** Fresh summary of the request. */
  summary(): Promise<PendingSummary> {
    return this.queue.getSummary(this.requestId);
  }
}

/* ---------------------------------- queue ---------------------------------- */

export class ApprovalQueue {
  private readonly dir: string;
  private readonly defaultTtlMs: number;
  private readonly hmacSecret: string;
  private readonly onExpire: ExpireBehavior;
  private readonly escalateTo?: string;
  private readonly approveUrlBase?: string;
  private readonly notifiers?: QueueNotifier;
  private readonly timers = new Map<string, NodeJS.Timeout>();

  constructor(opts: QueueOptions) {
    if (!opts.dir) throw new ApprovalStateError("createQueue requires a dir");
    if (!opts.hmacSecret) throw new ApprovalStateError("createQueue requires an hmacSecret");
    if (opts.onExpire === "escalate" && !opts.escalateTo) {
      throw new ApprovalStateError('onExpire "escalate" requires an escalateTo approver');
    }
    this.dir = path.resolve(opts.dir);
    mkdirSync(this.dir, { recursive: true });
    this.defaultTtlMs = opts.defaultTtlMs ?? 600_000;
    this.hmacSecret = opts.hmacSecret;
    this.onExpire = opts.onExpire ?? "deny";
    this.escalateTo = opts.escalateTo;
    this.approveUrlBase = opts.approveUrlBase;
    this.notifiers = opts.notifiers;
    // Resume: re-arm expiry timers for requests that were pending at shutdown.
    for (const summary of this.listPendingSync()) {
      this.scheduleExpiry(summary.id, summary.expiresAt);
    }
  }

  /* ------------------------------- persistence ------------------------------ */

  private requestPath(id: string): string {
    return path.join(this.dir, `${id}.json`);
  }

  private readStored(id: string): StoredApprovalRequest {
    let raw: string;
    try {
      raw = readFileSync(this.requestPath(id), "utf8");
    } catch {
      throw new ApprovalStateError(`unknown approval request ${id}`);
    }
    return JSON.parse(raw) as StoredApprovalRequest;
  }

  private writeStored(sr: StoredApprovalRequest): void {
    writeFileSync(this.requestPath(sr.id), JSON.stringify(sr, null, 2));
  }

  private audit(entry: {
    ts: string;
    requestId: string;
    event: string;
    actor: string;
    detail: Record<string, unknown>;
  }): void {
    appendFileSync(path.join(this.dir, "audit.jsonl"), JSON.stringify(entry) + "\n");
  }

  /* --------------------------------- timers --------------------------------- */

  private clearTimer(id: string): void {
    const t = this.timers.get(id);
    if (t) {
      clearTimeout(t);
      this.timers.delete(id);
    }
  }

  private scheduleExpiry(id: string, expiresAt: string): void {
    this.clearTimer(id);
    const delay = Math.max(0, Date.parse(expiresAt) - Date.now());
    const timer = setTimeout(() => {
      try {
        this.processExpiry(this.readStored(id));
      } catch {
        // File removed or unreadable; nothing to expire.
      }
    }, delay);
    timer.unref();
    this.timers.set(id, timer);
  }

  /* ------------------------------ state changes ----------------------------- */

  private ensurePending(sr: StoredApprovalRequest): void {
    if (sr.status !== "pending") {
      throw new ApprovalStateError(
        `request ${sr.id} is ${sr.status}, only pending requests can be decided`,
      );
    }
  }

  private ensureAuthorized(sr: StoredApprovalRequest, approverId: string): void {
    if (!sr.approvers.includes(approverId)) {
      throw new ApprovalStateError(
        `approver "${approverId}" is not authorized for request ${sr.id} (authorized: ${sr.approvers.join(", ") || "none"})`,
      );
    }
  }

  private emit(event: QueueEvent): void {
    const fn = this.notifiers?.onEvent;
    if (!fn) return;
    try {
      fn(event);
    } catch {
      // A notifier must never break the queue.
    }
  }

  private notifyWebhook(sr: StoredApprovalRequest): void {
    const url = this.notifiers?.webhookUrl;
    if (!url) return;
    const base = this.approveUrlBase?.replace(/\/$/, "");
    const payload = {
      text: `[approvalflow] ${sr.agent} requests approval: ${sr.action} (risk ${sr.risk ?? "n/a"})`,
      requestId: sr.id,
      action: sr.action,
      risk: sr.risk ?? null,
      approveUrlHint: base ? `${base}/${sr.id}` : `approvalflow://approvals/${sr.id}`,
    };
    try {
      fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      }).catch(() => {
        // Fire-and-forget: webhook failures never fail the submission.
      });
    } catch {
      // Synchronous fetch construction errors are equally non-fatal.
    }
  }

  private signDecision(input: Omit<ApprovalDecision, "signature" | "approverId">): ApprovalDecision {
    const signature = createHmac("sha256", this.hmacSecret)
      .update(canonicalDecisionPayload(input))
      .digest("hex");
    return { ...input, approverId: input.approverIds[0], signature };
  }

  /** Expiry core, shared by the timer path and the lazy check in listPending/wait. */
  private processExpiry(sr: StoredApprovalRequest): void {
    if (sr.status !== "pending") return;
    const now = nowIso();
    const eventBase = {
      requestId: sr.id,
      agent: sr.agent,
      action: sr.action,
      risk: sr.risk,
      at: now,
    };
    if (this.onExpire === "escalate" && this.escalateTo && !sr.escalatedOnce) {
      // Escalate once: reassign approvers, extend the TTL by one period, then re-arm.
      sr.escalatedOnce = true;
      sr.approvers = [this.escalateTo];
      sr.expiresAt = new Date(Date.now() + sr.ttlMs).toISOString();
      sr.escalations.push({ to: this.escalateTo, at: now, by: "expiry", reason: "auto-escalated on TTL expiry" });
      this.writeStored(sr);
      this.audit({
        ts: now,
        requestId: sr.id,
        event: "escalated",
        actor: "system",
        detail: { to: this.escalateTo, by: "expiry" },
      });
      this.emit({ ...eventBase, type: "escalated" });
      this.scheduleExpiry(sr.id, sr.expiresAt);
      return;
    }
    sr.status = "expired";
    this.writeStored(sr);
    this.clearTimer(sr.id);
    this.audit({ ts: now, requestId: sr.id, event: "expired", actor: "system", detail: {} });
    this.emit({ ...eventBase, type: "expired" });
    settleWaiters(this.dir, sr.id, { rejected: new ApprovalExpiredError(sr.id) });
  }

  /* -------------------------------- public API ------------------------------ */

  /** Submit a new approval request. Returns a handle whose wait() resolves on decision. */
  async submit(input: ApprovalRequestInput): Promise<PendingRequest> {
    if (!input.agent) throw new ApprovalStateError("submit requires an agent name");
    if (!input.action) throw new ApprovalStateError("submit requires an action");
    if (!input.approvers || input.approvers.length === 0) {
      throw new ApprovalStateError("submit requires at least one approver");
    }
    const quorum = input.quorum ?? 1;
    if (!Number.isInteger(quorum) || quorum < 1) {
      throw new ApprovalStateError("quorum must be a positive integer");
    }
    const ttlMs = input.ttlMs ?? this.defaultTtlMs;
    if (!(ttlMs > 0)) throw new ApprovalStateError("ttlMs must be positive");
    const now = Date.now();
    const sr: StoredApprovalRequest = {
      id: randomUUID(),
      agent: input.agent,
      action: input.action,
      params: input.params ?? {},
      risk: input.risk,
      context: input.context,
      approvers: [...input.approvers],
      quorum,
      approvals: [],
      delegations: [],
      escalations: [],
      status: "pending",
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + ttlMs).toISOString(),
      ttlMs,
      escalatedOnce: false,
    };
    this.writeStored(sr);
    this.audit({
      ts: sr.createdAt,
      requestId: sr.id,
      event: "submitted",
      actor: input.agent,
      detail: { action: input.action, approvers: sr.approvers, quorum, risk: input.risk ?? null },
    });
    this.scheduleExpiry(sr.id, sr.expiresAt);
    this.emit({
      type: "submitted",
      requestId: sr.id,
      agent: sr.agent,
      action: sr.action,
      risk: sr.risk,
      at: sr.createdAt,
    });
    this.notifyWebhook(sr);
    return new PendingRequest(this, sr.id);
  }

  /** Record an approval. Resolves waiters once quorum distinct approvers have approved. */
  async approve(id: string, opts: ApproveOptions): Promise<PendingSummary> {
    const sr = this.readStored(id);
    this.ensurePending(sr);
    this.ensureAuthorized(sr, opts.approverId);
    if (sr.approvals.some((a) => a.approverId === opts.approverId)) {
      // Idempotent: a second approval from the same approver never counts twice.
      this.audit({
        ts: nowIso(),
        requestId: id,
        event: "duplicate_approval",
        actor: opts.approverId,
        detail: {},
      });
      return toSummary(sr);
    }
    const at = nowIso();
    sr.approvals.push({ approverId: opts.approverId, at, reason: opts.reason });
    this.audit({
      ts: at,
      requestId: id,
      event: "approval_recorded",
      actor: opts.approverId,
      detail: { approvals: sr.approvals.length, quorum: sr.quorum, reason: opts.reason ?? null },
    });
    if (sr.approvals.length >= sr.quorum) {
      const decision = this.signDecision({
        requestId: id,
        approved: true,
        approverIds: sr.approvals.map((a) => a.approverId),
        decidedAt: at,
        reason: opts.reason,
      });
      sr.status = "approved";
      sr.decision = decision;
      this.writeStored(sr);
      this.clearTimer(id);
      this.audit({
        ts: at,
        requestId: id,
        event: "approved",
        actor: opts.approverId,
        detail: { approverIds: decision.approverIds },
      });
      this.emit({ type: "approved", requestId: id, agent: sr.agent, action: sr.action, risk: sr.risk, at });
      settleWaiters(this.dir, id, { resolved: decision });
    } else {
      this.writeStored(sr);
    }
    return toSummary(sr);
  }

  /** Deny a request. Waiters reject with ApprovalDeniedError carrying the signed decision. */
  async deny(id: string, opts: DenyOptions): Promise<PendingSummary> {
    const sr = this.readStored(id);
    this.ensurePending(sr);
    this.ensureAuthorized(sr, opts.approverId);
    const at = nowIso();
    const decision = this.signDecision({
      requestId: id,
      approved: false,
      approverIds: [opts.approverId],
      decidedAt: at,
      reason: opts.reason,
    });
    sr.status = "denied";
    sr.decision = decision;
    this.writeStored(sr);
    this.clearTimer(id);
    this.audit({
      ts: at,
      requestId: id,
      event: "denied",
      actor: opts.approverId,
      detail: { reason: opts.reason ?? null },
    });
    this.emit({ type: "denied", requestId: id, agent: sr.agent, action: sr.action, risk: sr.risk, at });
    settleWaiters(this.dir, id, { rejected: new ApprovalDeniedError(decision) });
    return toSummary(sr);
  }

  /** Delegate approval authority. The chain is recorded in order; the delegate joins the approver list. */
  async delegate(id: string, opts: DelegateOptions): Promise<PendingSummary> {
    const sr = this.readStored(id);
    this.ensurePending(sr);
    if (!opts.from || !opts.to) throw new ApprovalStateError("delegate requires from and to");
    const at = nowIso();
    sr.delegations.push({ from: opts.from, to: opts.to, at, reason: opts.reason });
    if (!sr.approvers.includes(opts.to)) sr.approvers.push(opts.to);
    this.writeStored(sr);
    this.audit({
      ts: at,
      requestId: id,
      event: "delegated",
      actor: opts.from,
      detail: { to: opts.to, reason: opts.reason ?? null },
    });
    this.emit({ type: "delegated", requestId: id, agent: sr.agent, action: sr.action, risk: sr.risk, at });
    return toSummary(sr);
  }

  /** Manually escalate: reassign approvers to one target, extend the TTL by one period. */
  async escalate(id: string, opts: EscalateOptions): Promise<PendingSummary> {
    const sr = this.readStored(id);
    this.ensurePending(sr);
    if (!opts.to) throw new ApprovalStateError("escalate requires a to approver");
    const at = nowIso();
    sr.approvers = [opts.to];
    sr.escalatedOnce = true;
    sr.expiresAt = new Date(Date.now() + sr.ttlMs).toISOString();
    sr.escalations.push({ to: opts.to, at, by: "manual", reason: opts.reason });
    this.writeStored(sr);
    this.audit({
      ts: at,
      requestId: id,
      event: "escalated",
      actor: "manual",
      detail: { to: opts.to, reason: opts.reason ?? null },
    });
    this.emit({ type: "escalated", requestId: id, agent: sr.agent, action: sr.action, risk: sr.risk, at });
    this.scheduleExpiry(id, sr.expiresAt);
    return toSummary(sr);
  }

  /** Wait for the decision. Resolves on approval, rejects on deny or expiry. Safe to call after restart. */
  async wait(id: string): Promise<ApprovalDecision> {
    const sr = this.readStored(id);
    if (sr.status === "approved" && sr.decision) return sr.decision;
    if (sr.status === "denied" && sr.decision) throw new ApprovalDeniedError(sr.decision);
    if (sr.status === "expired") throw new ApprovalExpiredError(id);
    if (Date.parse(sr.expiresAt) <= Date.now()) {
      this.processExpiry(this.readStored(id));
      return this.wait(id);
    }
    return new Promise<ApprovalDecision>((resolve, reject) => {
      waitersFor(this.dir, id).add({ resolve, reject });
    });
  }

  /** All currently pending requests, with expired ones lazily settled first. */
  listPending(): PendingSummary[] {
    return this.listPendingSync();
  }

  private listPendingSync(): PendingSummary[] {
    const out: PendingSummary[] = [];
    let files: string[];
    try {
      files = readdirSync(this.dir);
    } catch {
      return out;
    }
    for (const file of files) {
      if (!file.endsWith(".json") || file === "audit.jsonl") continue;
      let sr: StoredApprovalRequest;
      try {
        sr = JSON.parse(readFileSync(path.join(this.dir, file), "utf8")) as StoredApprovalRequest;
      } catch {
        continue;
      }
      if (sr.status === "pending" && Date.parse(sr.expiresAt) <= Date.now()) {
        this.processExpiry(sr);
        sr = this.readStored(sr.id);
      }
      if (sr.status === "pending") out.push(toSummary(sr));
    }
    return out;
  }

  /** Full stored record, including approvals, delegations, escalations, and the signed decision. */
  async getRequest(id: string): Promise<StoredApprovalRequest> {
    return this.readStored(id);
  }

  /** Synchronous variant used by PendingRequest.status. */
  getRequestSync(id: string): StoredApprovalRequest {
    return this.readStored(id);
  }

  async getSummary(id: string): Promise<PendingSummary> {
    return toSummary(this.readStored(id));
  }

  /** Verify an HMAC-SHA256 decision signature. Returns false on any tampering or wrong secret. */
  verifySignature(decision: ApprovalDecision): boolean {
    try {
      const { signature, ...rest } = decision;
      const expected = createHmac("sha256", this.hmacSecret)
        .update(canonicalDecisionPayload(rest))
        .digest("hex");
      const a = Buffer.from(signature, "utf8");
      const b = Buffer.from(expected, "utf8");
      return a.length === b.length && timingSafeEqual(a, b);
    } catch {
      return false;
    }
  }

  /** Stop all expiry timers. The file store is unaffected. */
  close(): void {
    for (const id of this.timers.keys()) this.clearTimer(id);
  }
}

/** Create a queue bound to a directory. Reloads pending requests so approvals survive restarts. */
export function createQueue(opts: QueueOptions): ApprovalQueue {
  return new ApprovalQueue(opts);
}

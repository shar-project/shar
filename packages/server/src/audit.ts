import type { AuditEvent, AuditStore } from "./types.js";

const AUDIT_BATCH_SIZE = 128;
const AUDIT_BATCH_WINDOW_MILLISECONDS = 10;

/**
 * Keeps best-effort audit persistence off the proof-critical path while
 * placing a hard bound on memory. State-store errors and a full queue are
 * counted through `onDropped`; neither may change challenge validity.
 */
export class BufferedAuditStore implements AuditStore {
  private readonly queue: AuditEvent[] = [];
  private drainPromise: Promise<void> | undefined;
  private drainTimer: ReturnType<typeof setTimeout> | undefined;
  private drainScheduled = false;
  private closing = false;

  constructor(
    private readonly inner: AuditStore,
    private readonly capacity = 4_096,
    private readonly onDropped: () => void = () => undefined,
  ) {
    if (!Number.isSafeInteger(capacity) || capacity < 1 || capacity > 65_536)
      throw new Error("invalid_audit_queue_capacity");
  }

  async record(event: AuditEvent): Promise<void> {
    if (this.closing) {
      this.dropped();
      return;
    }
    if (this.queue.length >= this.capacity) {
      this.dropped();
      return;
    }
    this.queue.push({ ...event });
    if (!this.drainPromise && !this.drainScheduled) this.scheduleDrain();
  }

  /**
   * Stop accepting new events and persist everything already accepted. Audit
   * failures are counted and swallowed, exactly as on the ordinary background
   * path. Hosts should await this after request admission has stopped and
   * before closing the underlying state client.
   */
  async flush(): Promise<void> {
    this.closing = true;
    if (this.drainTimer !== undefined) {
      clearTimeout(this.drainTimer);
      this.drainTimer = undefined;
    }
    this.drainScheduled = false;
    while (this.queue.length > 0 || this.drainPromise) {
      if (!this.drainPromise && this.queue.length > 0) this.startDrain();
      const active = this.drainPromise;
      if (active) await active;
    }
  }

  async list(
    tenant: string,
    siteKey: string,
    action: string,
    limit: number,
  ): Promise<AuditEvent[]> {
    if (!this.inner.list) throw new Error("audit_list_unavailable");
    return this.inner.list(tenant, siteKey, action, limit);
  }

  async purge(before: number): Promise<void> {
    await this.inner.purge?.(before);
  }

  private async drain(): Promise<void> {
    while (this.queue.length > 0) {
      const batch = this.queue.splice(0, AUDIT_BATCH_SIZE);
      try {
        if (this.inner.recordBatch) await this.inner.recordBatch(batch);
        else for (const event of batch) await this.inner.record(event);
      } catch {
        for (let index = 0; index < batch.length; index++) this.dropped();
      }
    }
  }

  private startDrain(): void {
    if (this.drainPromise) return;
    this.drainPromise = this.drain().finally(() => {
      this.drainPromise = undefined;
      if (this.queue.length > 0) {
        if (this.closing) this.startDrain();
        else this.scheduleDrain();
      }
    });
  }

  private scheduleDrain(): void {
    this.drainScheduled = true;
    if (this.inner.recordBatch) {
      this.drainTimer = setTimeout(() => {
        if (!this.drainScheduled) return;
        this.drainTimer = undefined;
        this.drainScheduled = false;
        this.startDrain();
      }, AUDIT_BATCH_WINDOW_MILLISECONDS);
    } else
      queueMicrotask(() => {
        if (!this.drainScheduled) return;
        this.drainScheduled = false;
        this.startDrain();
      });
  }

  private dropped(): void {
    try {
      this.onDropped();
    } catch {
      // Observing a dropped audit event is itself best effort.
    }
  }
}

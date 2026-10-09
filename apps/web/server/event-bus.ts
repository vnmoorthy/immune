import { newId, type ImmuneEvent, type ImmuneEventType } from '@immune/core';

export type EventHandler = (e: ImmuneEvent) => void;

/** In-process pub/sub with a bounded replay ring. One instance per engine; SSE clients subscribe. */
export class EventBus {
  private readonly subs = new Set<EventHandler>();
  private ring: ImmuneEvent[] = [];
  constructor(private readonly cap = 500) {}

  emit(type: ImmuneEventType, payload: unknown): ImmuneEvent {
    const e: ImmuneEvent = { id: newId('ev'), type, ts: Date.now(), payload };
    this.ring.push(e);
    if (this.ring.length > this.cap) this.ring.splice(0, this.ring.length - this.cap);
    for (const h of this.subs) {
      try {
        h(e);
      } catch (err) {
        console.error('[immune:bus] subscriber failed', err);
      }
    }
    return e;
  }

  subscribe(h: EventHandler): () => void {
    this.subs.add(h);
    return () => {
      this.subs.delete(h);
    };
  }

  recent(n = 100, types?: ImmuneEventType[]): ImmuneEvent[] {
    const list = types ? this.ring.filter((e) => types.includes(e.type)) : this.ring;
    return list.slice(-n);
  }

  get subscribers(): number {
    return this.subs.size;
  }
}

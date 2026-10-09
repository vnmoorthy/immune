'use client';

import { useState } from 'react';
import Link from 'next/link';
import { ExternalLink, FlaskConical } from 'lucide-react';
import type { Trace } from '@immune/core';
import { api } from '@/lib/api';
import { fmtDateTime, fmtMs, FAMILY_META, phaseOfTrace } from '@/lib/format';
import { DecisionTag, SeverityTag, Tag } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { CodeBlock, JsonBlock } from '@/components/ui/code-block';
import { Drawer } from '@/components/ui/drawer';
import { KV } from '@/components/ui/misc';
import { useToast } from '@/components/ui/toast';
import { ToolName } from '@/components/ui/tool-name';

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-4 border-t border-line pt-3 first:border-t-0 first:pt-0">
      <h3 className="label mb-2">{title}</h3>
      {children}
    </section>
  );
}

/** Render confusable / invisible characters explicitly so a spoofed name is visibly wrong. */
export function escapeConfusables(s: string): string {
  return s.replace(/[^\x20-\x7E]/g, (ch) => `\\u${ch.codePointAt(0)!.toString(16).padStart(4, '0')}`);
}

export function TraceDrawer({ trace, onClose, showExplorerLink = true }: { trace: Trace | null; onClose: () => void; showExplorerLink?: boolean }) {
  const { toast } = useToast();
  const [busy, setBusy] = useState(false);

  const remediate = async () => {
    if (!trace) return;
    setBusy(true);
    try {
      const r = await api.remediate(trace.id);
      toast({ title: 'Remediation started', description: `${r.remediationId} · follow it in the Theatre`, tone: 'info' });
    } catch (e) {
      toast({ title: 'Remediation refused', description: e instanceof Error ? e.message : String(e), tone: 'breach' });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Drawer
      open={!!trace}
      onClose={onClose}
      title={
        trace ? (
          <span className="flex items-center gap-3">
            <span className="font-mono text-[12.5px]">{trace.id}</span>
            <DecisionTag decision={trace.decision} breached={trace.breached} boxed />
          </span>
        ) : null
      }
      subtitle={trace ? `${FAMILY_META[trace.family]?.label ?? trace.family} · ${trace.variant} · ${trace.label} · ${fmtDateTime(trace.ts)}` : undefined}
    >
      {trace ? (
        <>
          <div className="mb-3 flex flex-wrap items-center gap-1.5">
            {trace.label === 'attack' ? (
              <Button variant={trace.breached ? 'danger' : 'default'} loading={busy} icon={<FlaskConical className="h-3.5 w-3.5" />} onClick={remediate} mono size="xs">
                {trace.breached ? 'remediate breach' : 'run remediation from trace'}
              </Button>
            ) : null}
            {showExplorerLink ? (
              <Link href={`/traces?id=${encodeURIComponent(trace.id)}`} className="focus-ring inline-flex h-6 items-center gap-1.5 border border-line px-2 font-mono text-[11px] uppercase tracking-[0.06em] text-fg-2 transition-colors hover:text-fg">
                <ExternalLink className="h-3 w-3" /> explorer
              </Link>
            ) : null}
          </div>

          <Section title="Decision">
            <KV
              rows={[
                { k: 'decision', v: <DecisionTag decision={trace.decision} breached={trace.breached} /> },
                { k: 'phase', v: phaseOfTrace(trace) },
                { k: 'tainted', v: trace.tainted ? <span className="text-flag">yes — an earlier result in this session was flagged</span> : 'no' },
                { k: 'blocked by', v: trace.blockedBy ? <Link className="text-info hover:underline" href={`/antibodies?rule=${encodeURIComponent(trace.blockedBy)}`}>{trace.blockedBy}</Link> : '—' },
                { k: 'citation', v: trace.citation ? <span className="font-sans text-[12px] text-fg">{trace.citation}</span> : '—' },
                { k: 'gate latency', v: fmtMs(trace.latencyMs) },
                { k: 'session', v: trace.sessionId },
              ]}
            />
          </Section>

          <Section title={`Findings · ${trace.findings.length}`}>
            {trace.findings.length === 0 ? (
              <p className="font-mono text-[11.5px] text-fg-3">no detector fired{trace.breached ? ' — this is why the attack got through' : ''}</p>
            ) : (
              <ul className="divide-y divide-line border border-line">
                {trace.findings.map((f, i) => (
                  <li key={i} className="px-2.5 py-2">
                    <div className="flex flex-wrap items-center gap-3">
                      <Tag tone="neutral">{f.detector}</Tag>
                      <SeverityTag severity={f.severity} />
                      {f.ruleId ? <span className="font-mono text-[10.5px] text-fg-3">{f.ruleId}</span> : null}
                    </div>
                    <div className="mt-1 text-[12px] text-fg">{f.message}</div>
                    <pre className="mt-1 whitespace-pre-wrap break-all font-mono text-[11px] leading-relaxed text-fg-2">{f.evidence}</pre>
                  </li>
                ))}
              </ul>
            )}
          </Section>

          {trace.toolDef ? (
            <Section title="Tool definition observed">
              <KV
                className="mb-2"
                rows={[
                  { k: 'server', v: trace.toolDef.server },
                  { k: 'name', v: <ToolName name={trace.toolDef.name} /> },
                  { k: 'capabilities', v: trace.toolDef.capabilities.join(', ') || '—' },
                  { k: 'hash', v: trace.toolDef.hash ? `${trace.toolDef.hash.slice(0, 16)}…` : '—' },
                ]}
              />
              <CodeBlock title="description" code={trace.toolDef.description} maxHeight={200} />
            </Section>
          ) : null}

          {trace.result ? (
            <Section title="Tool result the agent read">
              <KV className="mb-2" rows={[{ k: 'server · tool', v: `${trace.result.server} · ${trace.result.tool}` }]} />
              <CodeBlock title="content" code={trace.result.content} maxHeight={220} />
            </Section>
          ) : null}

          {trace.attemptedCall ? (
            <Section title="Call the agent attempted">
              <KV
                className="mb-2"
                rows={[
                  { k: 'server · tool', v: <span>{trace.attemptedCall.server} · <ToolName name={trace.attemptedCall.tool} /></span> },
                  { k: 'capabilities', v: trace.attemptedCall.capabilities.join(', ') || '—' },
                ]}
              />
              <JsonBlock title="args" value={trace.attemptedCall.args} maxHeight={220} />
            </Section>
          ) : null}

          <Section title="Full trace">
            <JsonBlock title="trace.json" value={trace} maxHeight={520} />
          </Section>
        </>
      ) : null}
    </Drawer>
  );
}

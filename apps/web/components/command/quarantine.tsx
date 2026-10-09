'use client';

import { useState } from 'react';
import { ShieldOff } from 'lucide-react';
import { api } from '@/lib/api';
import { useImmuneEvents } from '@/lib/events';
import { usePoll, useNow } from '@/lib/use-poll';
import { timeAgo } from '@/lib/format';
import { Panel } from '@/components/ui/panel';
import { Button } from '@/components/ui/button';
import { Empty } from '@/components/ui/misc';
import { useToast } from '@/components/ui/toast';
import { escapeConfusables } from '@/components/trace-drawer';
import { ToolName } from '@/components/ui/tool-name';
import { useMetrics } from './metrics-context';

export function Quarantine() {
  const q = usePoll(() => api.quarantine(), 8000);
  const { refresh: refreshMetrics } = useMetrics();
  const { toast } = useToast();
  const now = useNow(5000);
  const [busy, setBusy] = useState<string | null>(null);

  useImmuneEvents(() => void q.refresh(), ['quarantine', 'trace']);

  const release = async (server: string, tool: string) => {
    const key = `${server}/${tool}`;
    setBusy(key);
    try {
      const r = await api.release(server, tool);
      toast({ title: r.released ? 'Tool released' : 'Nothing to release', description: `${server} · ${escapeConfusables(tool)}`, tone: r.released ? 'immune' : 'neutral' });
      await q.refresh();
      void refreshMetrics();
    } catch (e) {
      toast({ title: 'Release failed', description: e instanceof Error ? e.message : String(e), tone: 'breach' });
    } finally {
      setBusy(null);
    }
  };

  const items = q.data ?? [];

  return (
    <Panel title="Quarantine" meta={`${items.length} tool${items.length === 1 ? '' : 's'} held`} className="col-span-12 border-0 lg:col-span-4" flush>
      <div className="h-[420px] overflow-y-auto">
        {items.length === 0 ? (
          <Empty
            title={q.loading ? 'Loading…' : 'No tools in quarantine'}
            hint={q.loading ? '/api/quarantine' : 'rug_pull and homoglyph_spoof put a definition here on sight'}
          />
        ) : (
          <ul className="divide-y divide-line">
            {items.map((it) => {
              const key = `${it.server}/${it.tool}`;
              return (
                <li key={key} className="rail-flag flex items-start gap-3 px-3 py-2.5">
                  <ShieldOff className="mt-0.5 h-3.5 w-3.5 shrink-0 text-flag" strokeWidth={1.6} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-mono text-[11.5px] text-fg" title={`${it.server} · ${it.tool}`}>
                      <span className="text-fg-3">{it.server}</span> · <ToolName name={it.tool} />
                    </div>
                    <div className="mt-0.5 text-[11.5px] leading-snug text-fg-2">{it.reason}</div>
                    <div className="mt-0.5 font-mono text-[10.5px] text-fg-3">
                      held {timeAgo(it.since, now)}
                      {it.traceId ? ` · ${it.traceId}` : ''}
                    </div>
                  </div>
                  <Button size="xs" mono loading={busy === key} onClick={() => release(it.server, it.tool)} title="Lift the hold — the tool may be called again">
                    release
                  </Button>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </Panel>
  );
}

'use client';

import { MetricsProvider } from './metrics-context';
import { Counters, Gauges, TtiHero } from './hero';
import { Arena } from './arena';
import { Theatre } from './theatre';
import { LiveWire } from './live-wire';
import { Quarantine } from './quarantine';

export function CommandCenter() {
  return (
    <MetricsProvider>
      <div className="flex flex-col gap-3">
        <div className="hairline-grid grid-cols-12">
          <TtiHero />
          <Gauges />
          <Counters />
        </div>
        <div className="hairline-grid grid-cols-12">
          <Arena />
          <Theatre />
        </div>
        <div className="hairline-grid grid-cols-12">
          <LiveWire />
          <Quarantine />
        </div>
      </div>
    </MetricsProvider>
  );
}

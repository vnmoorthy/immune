import type { Metadata } from 'next';
import { Suspense } from 'react';
import { TracesExplorer } from '@/components/traces/explorer';

export const metadata: Metadata = { title: 'Traces' };

export default function Page() {
  return (
    <Suspense fallback={null}>
      <TracesExplorer />
    </Suspense>
  );
}

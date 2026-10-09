import type { Metadata } from 'next';
import { Suspense } from 'react';
import { RulesTable } from '@/components/antibodies/rules-table';

export const metadata: Metadata = { title: 'Antibodies' };

export default function Page() {
  return (
    <Suspense fallback={null}>
      <RulesTable />
    </Suspense>
  );
}

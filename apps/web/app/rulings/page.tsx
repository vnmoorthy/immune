import type { Metadata } from 'next';
import { Suspense } from 'react';
import { RulingsList } from '@/components/rulings/rulings-list';

export const metadata: Metadata = { title: 'Rulings' };

export default function Page() {
  return (
    <Suspense fallback={null}>
      <RulingsList />
    </Suspense>
  );
}

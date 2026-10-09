import type { Metadata } from 'next';
import { Suspense } from 'react';
import { ReceiptsList } from '@/components/receipts/receipts-list';

export const metadata: Metadata = { title: 'Receipts' };

export default function Page() {
  return (
    <Suspense fallback={null}>
      <ReceiptsList />
    </Suspense>
  );
}

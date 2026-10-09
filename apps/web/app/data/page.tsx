import type { Metadata } from 'next';
import { DataPanel } from '@/components/data/data-panel';

export const metadata: Metadata = { title: 'Data' };

export default function Page() {
  return <DataPanel />;
}

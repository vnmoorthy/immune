import type { Metadata } from 'next';
import { CommandCenter } from '@/components/command/command-center';

export const metadata: Metadata = { title: 'Immune — Command' };

export default function Page() {
  return <CommandCenter />;
}

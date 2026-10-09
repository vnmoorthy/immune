'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import clsx from 'clsx';
import { Activity, Database, FileSignature, Gavel, ListTree, Microscope, type LucideIcon } from 'lucide-react';

const SECTIONS: { href: string; label: string; icon: LucideIcon; key: string }[] = [
  { href: '/', label: 'Command', icon: Activity, key: 'C' },
  { href: '/antibodies', label: 'Antibodies', icon: Microscope, key: 'A' },
  { href: '/receipts', label: 'Receipts', icon: FileSignature, key: 'R' },
  { href: '/rulings', label: 'Rulings', icon: Gavel, key: 'U' },
  { href: '/traces', label: 'Traces', icon: ListTree, key: 'T' },
  { href: '/data', label: 'Data', icon: Database, key: 'D' },
];

export function Mark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 16 16" className={clsx('h-4 w-4', className)} aria-hidden>
      <path d="M8 1.5 13 3.5v4.2c0 3-2.1 5.4-5 6.4-2.9-1-5-3.4-5-6.4V3.5L8 1.5Z" fill="none" stroke="currentColor" strokeWidth="1.25" strokeLinejoin="round" />
      <path d="M5.5 8 7.3 9.8 10.8 6.3" fill="none" stroke="currentColor" strokeWidth="1.25" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function Rail() {
  const pathname = usePathname();
  return (
    <aside className="sticky top-0 z-50 flex h-screen w-14 shrink-0 flex-col border-r border-line bg-surface-1 xl:w-[200px]">
      <Link href="/" className="focus-ring flex h-10 items-center gap-2.5 border-b border-line px-[18px] text-fg xl:px-4">
        <Mark className="shrink-0 text-fg" />
        <span className="hidden text-[12px] font-semibold tracking-[0.18em] xl:inline">IMMUNE</span>
      </Link>
      <nav className="flex flex-1 flex-col py-2">
        {SECTIONS.map((s) => {
          const active = s.href === '/' ? pathname === '/' : pathname.startsWith(s.href);
          const Icon = s.icon;
          return (
            <Link
              key={s.href}
              href={s.href}
              title={s.label}
              aria-current={active ? 'page' : undefined}
              className={clsx(
                'focus-ring relative flex h-9 items-center gap-3 px-[18px] text-[12px] transition-colors duration-150 ease-out xl:px-4',
                active ? 'bg-surface-2 text-fg' : 'text-fg-2 hover:bg-surface-2 hover:text-fg',
              )}
            >
              {active ? <span className="absolute inset-y-0 left-0 w-0.5 bg-info" /> : null}
              <Icon className="h-4 w-4 shrink-0" strokeWidth={1.6} />
              <span className="label hidden !text-inherit xl:inline">{s.label}</span>
            </Link>
          );
        })}
      </nav>
      <div className="hidden border-t border-line px-4 py-3 font-mono text-[10px] leading-4 text-fg-3 xl:block">
        <div>MCP FIREWALL</div>
        <div>REPLAY · PROVE · SIGN</div>
      </div>
    </aside>
  );
}

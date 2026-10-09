import clsx from 'clsx';
import type { ReactNode } from 'react';

/**
 * Panel: a surface with a 32px header row. Place inside a `hairline-grid` (border-0) or standalone.
 */
export function Panel({
  title,
  meta,
  actions,
  children,
  className,
  bodyClassName,
  flush,
  rail,
}: {
  title?: ReactNode;
  meta?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  flush?: boolean;
  rail?: 'breach' | 'flag' | 'immune' | 'info';
}) {
  return (
    <section className={clsx('flex min-w-0 flex-col bg-surface-1', rail && `rail-${rail}`, className)}>
      {title || actions || meta ? (
        <header className="flex h-8 shrink-0 items-center justify-between gap-3 border-b border-line px-3">
          <div className="flex min-w-0 items-center gap-3">
            {title ? <h2 className="label truncate">{title}</h2> : null}
            {meta ? <span className="truncate font-mono text-[11px] text-fg-3">{meta}</span> : null}
          </div>
          {actions ? <div className="flex shrink-0 items-center gap-1.5">{actions}</div> : null}
        </header>
      ) : null}
      <div className={clsx('min-h-0 min-w-0 flex-1', !flush && 'p-3', bodyClassName)}>{children}</div>
    </section>
  );
}

export function PageHeader({ title, meta, actions }: { title: ReactNode; meta?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-2 flex h-8 items-center justify-between gap-3">
      <div className="flex items-baseline gap-3">
        <h1 className="text-[13px] font-semibold uppercase tracking-[0.08em] text-fg">{title}</h1>
        {meta ? <span className="font-mono text-[11px] text-fg-3">{meta}</span> : null}
      </div>
      {actions ? <div className="flex items-center gap-1.5">{actions}</div> : null}
    </div>
  );
}

'use client';

import clsx from 'clsx';
import { Loader2 } from 'lucide-react';
import type { ButtonHTMLAttributes, ReactNode } from 'react';

type Variant = 'primary' | 'default' | 'danger' | 'ghost' | 'immune' | 'flag';
type Size = 'xs' | 'sm' | 'md';

const VARIANT: Record<Variant, string> = {
  primary: 'bg-info text-white border border-info hover:bg-[#3f7fe9] hover:border-[#3f7fe9]',
  default: 'bg-surface-2 text-fg border border-line hover:border-line-strong hover:bg-surface-3',
  danger: 'bg-transparent text-breach border border-breach/50 hover:bg-breach/10 hover:border-breach',
  immune: 'bg-transparent text-immune border border-immune/50 hover:bg-immune/10 hover:border-immune',
  flag: 'bg-transparent text-flag border border-flag/50 hover:bg-flag/10 hover:border-flag',
  ghost: 'bg-transparent text-fg-2 border border-transparent hover:text-fg hover:bg-surface-2',
};

const SIZE: Record<Size, string> = {
  xs: 'h-6 px-2 text-[11px] gap-1.5',
  sm: 'h-7 px-2.5 text-[12px] gap-1.5',
  md: 'h-8 px-3 text-[12.5px] gap-2',
};

export function Button({
  variant = 'default',
  size = 'sm',
  loading,
  icon,
  children,
  className,
  disabled,
  mono,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: Variant;
  size?: Size;
  loading?: boolean;
  icon?: ReactNode;
  mono?: boolean;
}) {
  return (
    <button
      type="button"
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={clsx(
        'focus-ring inline-flex shrink-0 select-none items-center justify-center whitespace-nowrap rounded-xs font-medium transition-colors duration-150 ease-out disabled:cursor-not-allowed disabled:opacity-40',
        mono && 'font-mono uppercase tracking-[0.06em]',
        VARIANT[variant],
        SIZE[size],
        className,
      )}
      {...rest}
    >
      {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : icon}
      {children}
    </button>
  );
}

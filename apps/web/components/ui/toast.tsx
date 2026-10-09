'use client';

import { createContext, useCallback, useContext, useMemo, useRef, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { X } from 'lucide-react';
import clsx from 'clsx';
import type { Tone } from '@/lib/format';

export interface ToastInput {
  title: string;
  description?: string;
  tone?: Tone;
  durationMs?: number;
}

interface ToastItem extends ToastInput {
  id: number;
}

interface ToastContextValue {
  toast: (t: ToastInput) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

const RAIL: Record<Tone, string> = {
  immune: 'rail-immune',
  breach: 'rail-breach',
  flag: 'rail-flag',
  quarantine: 'rail-breach',
  info: 'rail-info',
  neutral: 'rail-muted',
};

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const counter = useRef(0);

  const dismiss = useCallback((id: number) => setItems((xs) => xs.filter((x) => x.id !== id)), []);

  const toast = useCallback(
    (t: ToastInput) => {
      const id = ++counter.current;
      setItems((xs) => [...xs.slice(-4), { ...t, id }]);
      const ttl = t.durationMs ?? (t.tone === 'breach' ? 7000 : 4000);
      setTimeout(() => dismiss(id), ttl);
    },
    [dismiss],
  );

  const value = useMemo(() => ({ toast }), [toast]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="pointer-events-none fixed bottom-10 right-3 z-[100] flex w-[380px] max-w-[calc(100vw-1.5rem)] flex-col gap-1.5">
        <AnimatePresence initial={false}>
          {items.map((t) => (
            <motion.div
              key={t.id}
              layout
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.15, ease: [0, 0, 0.2, 1] }}
              role="status"
              className={clsx('pointer-events-auto flex items-start gap-3 border border-line-strong bg-surface-2 px-3 py-2.5', RAIL[t.tone ?? 'neutral'])}
            >
              <div className="min-w-0 flex-1">
                <div className="text-[12.5px] font-medium text-fg">{t.title}</div>
                {t.description ? <div className="mt-0.5 break-words font-mono text-[11px] leading-relaxed text-fg-2">{t.description}</div> : null}
              </div>
              <button onClick={() => dismiss(t.id)} className="focus-ring -mr-1 -mt-0.5 p-1 text-fg-3 transition-colors hover:text-fg" aria-label="Dismiss">
                <X className="h-3.5 w-3.5" />
              </button>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used inside <ToastProvider>');
  return ctx;
}

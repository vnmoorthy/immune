'use client';

import { useEffect } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { X } from 'lucide-react';
import type { ReactNode } from 'react';

export function Drawer({ open, onClose, title, subtitle, children, width = 680 }: { open: boolean; onClose: () => void; title: ReactNode; subtitle?: ReactNode; children: ReactNode; width?: number }) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  return (
    <AnimatePresence>
      {open ? (
        <>
          <motion.div
            key="backdrop"
            className="fixed inset-0 z-[60] bg-black/55"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15, ease: [0, 0, 0.2, 1] }}
            onClick={onClose}
          />
          <motion.aside
            key="panel"
            className="fixed inset-y-0 right-0 z-[70] flex w-full flex-col border-l border-line-strong bg-surface-1"
            style={{ maxWidth: width }}
            initial={{ x: 16, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: 16, opacity: 0 }}
            transition={{ duration: 0.16, ease: [0, 0, 0.2, 1] }}
            role="dialog"
            aria-modal
          >
            <header className="flex h-12 shrink-0 items-center justify-between gap-3 border-b border-line px-4">
              <div className="min-w-0">
                <div className="truncate text-[13px] font-medium text-fg">{title}</div>
                {subtitle ? <div className="truncate font-mono text-[11px] text-fg-3">{subtitle}</div> : null}
              </div>
              <button onClick={onClose} className="focus-ring p-1.5 text-fg-3 transition-colors hover:bg-surface-2 hover:text-fg" aria-label="Close">
                <X className="h-4 w-4" />
              </button>
            </header>
            <div className="min-h-0 flex-1 overflow-y-auto px-4 py-3">{children}</div>
          </motion.aside>
        </>
      ) : null}
    </AnimatePresence>
  );
}

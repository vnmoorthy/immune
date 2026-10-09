'use client';

import { useState } from 'react';
import clsx from 'clsx';
import { Check, Copy } from 'lucide-react';

export function CodeBlock({ code, language, className, maxHeight = 360, title }: { code: string; language?: string; className?: string; maxHeight?: number; title?: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      /* clipboard unavailable */
    }
  };
  return (
    <div className={clsx('inset relative overflow-hidden', className)}>
      <div className="flex h-6 items-center justify-between border-b border-line px-2">
        <span className="font-mono text-[10px] uppercase tracking-[0.08em] text-fg-3">{title ?? language ?? 'text'}</span>
        <button onClick={copy} className="focus-ring flex items-center gap-1 px-1 font-mono text-[10px] text-fg-3 transition-colors hover:text-fg">
          {copied ? <Check className="h-3 w-3 text-immune" /> : <Copy className="h-3 w-3" />}
          {copied ? 'copied' : 'copy'}
        </button>
      </div>
      <pre className="overflow-auto p-2.5 font-mono text-[11.5px] leading-[1.5] text-fg-2" style={{ maxHeight }}>
        <code>{code}</code>
      </pre>
    </div>
  );
}

export function JsonBlock({ value, maxHeight = 480, title = 'json' }: { value: unknown; maxHeight?: number; title?: string }) {
  const text = JSON.stringify(value, null, 2) ?? 'undefined';
  return <CodeBlock code={text} language="json" title={title} maxHeight={maxHeight} />;
}

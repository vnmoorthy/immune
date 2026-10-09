import clsx from 'clsx';

const NAMES: Record<number, string> = {
  0x0430: 'CYRILLIC SMALL LETTER A',
  0x0435: 'CYRILLIC SMALL LETTER IE',
  0x043e: 'CYRILLIC SMALL LETTER O',
  0x0440: 'CYRILLIC SMALL LETTER ER',
  0x0441: 'CYRILLIC SMALL LETTER ES',
  0x0443: 'CYRILLIC SMALL LETTER U',
  0x0445: 'CYRILLIC SMALL LETTER HA',
  0x0455: 'CYRILLIC SMALL LETTER DZE',
  0x0456: 'CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I',
  0x0458: 'CYRILLIC SMALL LETTER JE',
  0x04bb: 'CYRILLIC SMALL LETTER SHHA',
  0x0501: 'CYRILLIC SMALL LETTER KOMI DE',
  0x03bf: 'GREEK SMALL LETTER OMICRON',
  0x03b1: 'GREEK SMALL LETTER ALPHA',
  0x0261: 'LATIN SMALL LETTER SCRIPT G',
  0x00a0: 'NO-BREAK SPACE',
  0x200b: 'ZERO WIDTH SPACE',
  0x200c: 'ZERO WIDTH NON-JOINER',
  0x200d: 'ZERO WIDTH JOINER',
  0x2060: 'WORD JOINER',
  0xfeff: 'ZERO WIDTH NO-BREAK SPACE',
  0x2010: 'HYPHEN',
  0x2011: 'NON-BREAKING HYPHEN',
  0x2212: 'MINUS SIGN',
  0x1d5c6: 'MATHEMATICAL SANS-SERIF SMALL M',
};

const INVISIBLE = new Set([0x00a0, 0x200b, 0x200c, 0x200d, 0x2060, 0xfeff]);

export function describeCodePoint(cp: number): string {
  return `U+${cp.toString(16).toUpperCase().padStart(4, '0')} ${NAMES[cp] ?? 'NON-ASCII CHARACTER'}`;
}

export function hasConfusables(s: string): boolean {
  return /[^\x20-\x7e]/.test(s);
}

/**
 * Renders a tool / server name exactly as received. Every non-ASCII code point (Cyrillic look-alikes,
 * zero-width joiners…) is wrapped in a red-underlined span whose title names the code point, so a spoofed
 * name is visibly wrong instead of silently passing as the trusted one.
 */
export function ToolName({ name, className }: { name: string; className?: string }) {
  if (!hasConfusables(name)) return <span className={className}>{name}</span>;
  const parts = Array.from(name);
  return (
    <span className={className} title={name}>
      {parts.map((ch, i) => {
        const cp = ch.codePointAt(0)!;
        if (cp >= 0x20 && cp <= 0x7e) return <span key={i}>{ch}</span>;
        const invisible = INVISIBLE.has(cp);
        return (
          <span
            key={i}
            title={describeCodePoint(cp)}
            className={clsx('text-breach underline decoration-breach decoration-2 underline-offset-2', invisible && 'px-px opacity-90')}
          >
            {invisible ? '▯' : ch}
          </span>
        );
      })}
    </span>
  );
}

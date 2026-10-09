import type { Metadata, Viewport } from 'next';
import { Geist, JetBrains_Mono } from 'next/font/google';
import './globals.css';
import { Rail } from '@/components/shell/rail';
import { CommandBar } from '@/components/shell/command-bar';
import { Footer } from '@/components/shell/footer';
import { EventsProvider } from '@/lib/events';
import { ToastProvider } from '@/components/ui/toast';

const sans = Geist({ subsets: ['latin'], variable: '--font-geist', display: 'swap' });
const mono = JetBrains_Mono({ subsets: ['latin'], variable: '--font-jb-mono', display: 'swap' });

export const metadata: Metadata = {
  title: { default: 'Immune — Command', template: '%s · Immune' },
  description:
    'Immune turns every agent attack into an antibody: MCP firewall → replayable breach trace → synthesized countermeasure → replay-proven → signed receipt → the next agent is immune.',
  applicationName: 'Immune',
};

export const viewport: Viewport = {
  themeColor: '#0b0c0e',
  colorScheme: 'dark',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable} dark`} suppressHydrationWarning>
      <body className="min-h-screen bg-bg font-sans text-fg antialiased">
        <EventsProvider>
          <ToastProvider>
            <div className="flex min-h-screen">
              <Rail />
              <div className="flex min-w-0 flex-1 flex-col">
                <CommandBar />
                <main className="flex-1 p-3">{children}</main>
                <Footer />
              </div>
            </div>
          </ToastProvider>
        </EventsProvider>
      </body>
    </html>
  );
}

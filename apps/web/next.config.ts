import path from 'node:path';
import type { NextConfig } from 'next';

const monorepoRoot = path.resolve(__dirname, '../..');

const nextConfig: NextConfig = {
  // @immune/core and @immune/demo ship raw TypeScript (main: ./src/index.ts) — compile them in-place.
  transpilePackages: ['@immune/core', '@immune/demo'],
  outputFileTracingRoot: monorepoRoot,
  reactStrictMode: true,
  devIndicators: false,
  // integrations/senso/senso-cli.ts lives outside apps/web and is imported with a relative path.
  experimental: { externalDir: true },
  poweredByHeader: false,
  typescript: { ignoreBuildErrors: false },
  env: {
    IMMUNE_WEB_VERSION: process.env.npm_package_version ?? '0.1.0',
  },
  // @immune/core and @immune/demo use ESM-style `./x.js` specifiers for TypeScript sources.
  webpack: (config) => {
    config.resolve ??= {};
    config.resolve.extensionAlias = {
      '.js': ['.ts', '.tsx', '.js'],
      '.mjs': ['.mts', '.mjs'],
      '.jsx': ['.tsx', '.jsx'],
      ...(config.resolve.extensionAlias ?? {}),
    };
    return config;
  },
  turbopack: {
    resolveExtensions: ['.tsx', '.ts', '.jsx', '.js', '.mjs', '.json'],
  },
};

export default nextConfig;

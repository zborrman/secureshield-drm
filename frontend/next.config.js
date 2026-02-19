/** @type {import('next').NextConfig} */
const nextConfig = {
  // Next.js 16: Turbopack is default — WASM supported natively
  turbopack: {},
  // Kept for non-Turbopack builds (CI, docker build)
  webpack: (config) => {
    config.experiments = { ...config.experiments, asyncWebAssembly: true };
    return config;
  },
};

module.exports = nextConfig;

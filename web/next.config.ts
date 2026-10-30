import type { NextConfig } from "next";

const config: NextConfig = {
  reactStrictMode: true,
  // Dashboard talks to the API directly (CORS allow-listed in api/scanu_api/config.py).
  poweredByHeader: false,
};

export default config;

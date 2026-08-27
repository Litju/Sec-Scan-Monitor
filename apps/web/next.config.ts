import path from "node:path";
import type { NextConfig } from "next";
import { withWorkflow } from "workflow/next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  turbopack: { root: path.resolve(process.cwd(), "../..") },
  transpilePackages: ["@secscanmonitor/client", "@secscanmonitor/experience-contracts"],
};

export default withWorkflow(nextConfig);

import type { NextConfig } from "next";
import { withWorkflow } from "workflow/next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  transpilePackages: ["@secscanmonitor/client", "@secscanmonitor/experience-contracts"],
};

export default withWorkflow(nextConfig);

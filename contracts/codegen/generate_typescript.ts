/**
 * FL-001 scaffold placeholder for TypeScript contract generation.
 *
 * This file intentionally avoids implementing downstream code generation logic.
 * It exists only to establish the approved contracts/codegen package shape for
 * later milestones.
 */

import { resolve } from "node:path";

function main(): number {
  const schemasDir = resolve(__dirname, "..", "schemas");
  console.log("FL-001 scaffold only.");
  console.log(`Schemas directory: ${schemasDir}`);
  console.log("TypeScript code generation begins in FL-006.");
  return 0;
}

process.exitCode = main();

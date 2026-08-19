export const productTerminology = {
  Engagement: "Case",
  AgentRun: "Activity",
  Capability: "Tool",
  "OPA Decision": "Permission decision",
  Adjudication: "Review decision",
  EvidenceObject: "Evidence",
  TargetSnapshot: "Snapshot",
} as const;

export type ProductTerm = keyof typeof productTerminology;

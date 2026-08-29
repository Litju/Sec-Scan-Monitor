import { ApiError, createCanonicalClient } from "../../../packages/secscan-client/src/index.ts";
import { emptyExperienceSnapshot, isExperienceSnapshot, type DataMode, type ExperienceSnapshot } from "../../../packages/secscan-experience-contracts/src/index.ts";
import { previewExperienceSnapshot as previewFixture } from "../../../packages/secscan-experience-contracts/src/preview.ts";

function configuredMode(): DataMode | null {
  const value = process.env.SECSCAN_MODE?.trim().toUpperCase();
  if (!value) return "PREVIEW";
  if (value === "PREVIEW" || value === "LOCAL_INTEGRATED" || value === "HOSTED_INTEGRATED") return value;
  return null;
}

export async function loadTuiSnapshot(): Promise<ExperienceSnapshot> {
  const mode = configuredMode();
  if (!mode) return emptyExperienceSnapshot("LOCAL_INTEGRATED", "CONFIGURATION_INVALID / no canonical state selected");
  if (mode === "PREVIEW") return { ...previewFixture };

  const api = createCanonicalClient({
    mode,
    baseUrl: process.env.SECSCAN_API_URL?.trim() || "http://127.0.0.1:8000/api/secscan",
    principal: process.env.SECSCAN_PRINCIPAL,
  });
  try {
    const snapshot = await api.get<unknown>("/experience");
    if (!isExperienceSnapshot(snapshot)) return emptyExperienceSnapshot(mode, `${mode} / malformed canonical experience projection`);
    return { ...snapshot, mode };
  } catch (error) {
    const source = error instanceof ApiError && error.status === 404
      ? `${mode} / canonical experience projection is not exposed`
      : `${mode} / canonical experience API unavailable`;
    return emptyExperienceSnapshot(mode, source);
  }
}

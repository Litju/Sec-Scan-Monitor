import assert from "node:assert/strict";
import test from "node:test";
import { applyStreamUpdate, createLiveProjection, isExperienceSnapshot, safeDisplay, ScopeMismatchError, setLiveConnectionState, type StreamEnvelope } from "../../../packages/secscan-experience-contracts/src/index.ts";
import { previewExperienceSnapshot } from "../../../packages/secscan-experience-contracts/src/preview.ts";

type Item = { id: string; value: string };
const scope = { tenantId: "tenant-1", caseId: "case-1" };
const envelope = (updateId: string, value: string, sequence: number, version = sequence, objectId = "item-1", updateType: StreamEnvelope<Item>["updateType"] = "upsert"): StreamEnvelope<Item> => ({ updateId, objectId, updateType, observedAt: "2026-08-26T00:00:00Z", sequence, version, resumeCursor: `cursor-${sequence}`, scope, payload: { id: objectId, value } });

test("live projections reject duplicate and stale updates", () => {
  const first = applyStreamUpdate(createLiveProjection<Item>(), envelope("u1", "new", 2), scope);
  assert.equal(first.result, "accepted");
  assert.equal(applyStreamUpdate(first.projection, envelope("u1", "new", 2), scope).result, "duplicate");
  assert.equal(applyStreamUpdate(first.projection, envelope("u0", "old", 1), scope).result, "stale");
});

test("live projections preserve resume state across disconnect and recovery", () => {
  const initial = applyStreamUpdate(createLiveProjection<Item>(), envelope("u10", "initial", 10, 10, "item-1", "snapshot"), scope);
  const eventN = applyStreamUpdate(initial.projection, envelope("u11", "n", 11), scope);
  const eventN1 = applyStreamUpdate(eventN.projection, envelope("u12", "n+1", 12), scope);
  const disconnected = setLiveConnectionState(eventN1.projection, "DEGRADED");

  assert.equal(disconnected.connectionState, "DEGRADED");
  assert.equal(disconnected.resumeCursor, "cursor-12");
  assert.equal(applyStreamUpdate(disconnected, envelope("u12", "n+1", 12), scope).result, "duplicate");
  assert.equal(disconnected.items.length, 1);

  const recovered = setLiveConnectionState(disconnected, "CONNECTED");
  assert.equal(recovered.connectionState, "CONNECTED");
  const eventN2 = applyStreamUpdate(recovered, envelope("u13", "n+2", 13), scope);
  assert.equal(eventN2.result, "accepted");
  assert.equal(eventN2.projection.items[0]?.value, "n+2");
  assert.equal(applyStreamUpdate(eventN2.projection, envelope("u11-replay", "n", 11), scope).result, "stale");
  assert.equal(applyStreamUpdate(eventN2.projection, envelope("u9-out-of-order", "foreign-order", 9, 14, "item-2"), scope).result, "stale");
  assert.equal(eventN2.projection.items.length, 1);

  const unavailable = setLiveConnectionState(eventN2.projection, "UNAVAILABLE");
  assert.equal(unavailable.connectionState, "UNAVAILABLE");
  assert.equal(unavailable.items[0]?.value, "n+2");
  assert.equal(setLiveConnectionState(unavailable, "CONNECTED").connectionState, "CONNECTED");
});

test("display sanitizes terminal control sequences and secret-like values", () => {
  const displayed = safeDisplay("\u001b[31mBearer abc.def.ghi token=secret-value\u001b[0m");
  assert.equal(displayed, "Bearer <REDACTED> token=<REDACTED>");
});

test("live projections refuse cross-tenant and cross-case updates", () => {
  assert.throws(() => applyStreamUpdate(createLiveProjection<Item>(), envelope("u-cross", "foreign", 1), { tenantId: "tenant-2", caseId: "case-1" }), ScopeMismatchError);
  assert.throws(() => applyStreamUpdate(createLiveProjection<Item>(), envelope("u-cross-case", "foreign", 1), { tenantId: "tenant-1", caseId: "case-2" }), ScopeMismatchError);
});

test("malformed graph projections are rejected at the client boundary", () => {
  assert.equal(isExperienceSnapshot(previewExperienceSnapshot), true);
  assert.equal(isExperienceSnapshot({ ...previewExperienceSnapshot, graphNodes: [{}] }), false);
});

test("detection-response projections stay available as distinct scoped records", () => {
  assert.equal(previewExperienceSnapshot.detectionSignals?.[0]?.signalId, "SIG-PREV-022-001");
  assert.equal(previewExperienceSnapshot.hunts?.[0]?.huntId, "HUNT-PREV-022-001");
  assert.equal(previewExperienceSnapshot.incidents?.[0]?.state, "CONFIRMED");
  assert.equal(previewExperienceSnapshot.responseProposals?.[0]?.humanApprovalState, "APPROVAL_REQUIRED");
  assert.equal(isExperienceSnapshot(previewExperienceSnapshot), true);
});

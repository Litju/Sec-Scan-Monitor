import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryProvider } from "@/components/firm/QueryProvider";
import { NuqsTestingAdapter } from "nuqs/adapters/testing";
import { describe, expect, it } from "vitest";
import { ProductSurface } from "@/components/firm/ProductSurface";

describe("SecScanMonitor product surface", () => {
  const renderSurface = (surface: Parameters<typeof ProductSurface>[0]["initialSurface"]) => render(<QueryProvider><NuqsTestingAdapter><ProductSurface initialSurface={surface} /></NuqsTestingAdapter></QueryProvider>);

  it("renders attention-first Today as a preview-safe surface", () => {
    renderSurface("today");
    expect(screen.getByRole("heading", { name: "Today" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "1 things need your attention" })).toBeInTheDocument();
    expect(screen.getByText("Needs You")).toBeInTheDocument();
    expect(screen.getByText("Preview · read-only")).toBeInTheDocument();
    expect(screen.queryByText("Context stays intact")).not.toBeInTheDocument();
  });

  it("supports keyboard command navigation without mutation commands", async () => {
    const user = userEvent.setup();
    renderSurface("today");
    fireEvent.keyDown(window, { key: "k", ctrlKey: true });
    const palette = screen.getByRole("dialog", { name: "Search and ask" });
    expect(palette).toBeInTheDocument();
    const input = screen.getByRole("combobox", { name: /Search/ });
    await user.type(input, "ENG-PUBLIC-015");
    await user.keyboard("{Enter}");
    expect(screen.getByRole("heading", { name: "Case ENG-PUBLIC-015" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Overview" })).toBeInTheDocument();
  });

  it("opens a grounded assistant lens instead of turning the product into chat-first UI", async () => {
    const user = userEvent.setup();
    renderSurface("today");
    await user.click(screen.getByRole("button", { name: "Open search and ask" }));
    await user.click(screen.getByRole("option", { name: /Ask SecScanMonitor/i }));
    expect(screen.getByRole("dialog", { name: "Ask SecScanMonitor" })).toBeInTheDocument();
    expect(screen.getByText(/PREVIEW RESPONSE · NOT CONNECTED/i)).toBeInTheDocument();
    expect(screen.getByText(/cannot approve, mutate, change findings/i)).toBeInTheDocument();
  });

  it("keeps approval mutation controls disabled in preview mode", async () => {
    const user = userEvent.setup();
    renderSurface("approvals");
    const approve = screen.getByRole("button", { name: "Approve this action" });
    expect(approve).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Open search and ask" }));
    await user.click(screen.getByRole("option", { name: /Ask SecScanMonitor/i }));
    expect(screen.getByRole("dialog", { name: "Ask SecScanMonitor" })).toBeInTheDocument();
  });
});

import { render, screen } from "@testing-library/react";
import { QueryProvider } from "@/components/firm/QueryProvider";
import { describe, expect, it } from "vitest";
import { ProductSurface } from "@/components/firm/ProductSurface";

describe("semantic state presentation", () => {
  it("keeps finding severity and confidence as separate readable axes", () => {
    render(<QueryProvider><ProductSurface initialSurface="findings" initialId="FND-PREV-015" /></QueryProvider>);
    expect(screen.getByText("Severity")).toBeInTheDocument();
    expect(screen.getAllByText("Confidence").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Low").length).toBeGreaterThan(0);
    expect(screen.getAllByText("high").length).toBeGreaterThan(0);
  });

  it("keeps evidence metadata visible while raw bytes remain withheld", () => {
    render(<QueryProvider><ProductSurface initialSurface="evidence" initialId="E-1181" /></QueryProvider>);
    expect(screen.getByRole("heading", { name: "Evidence" })).toBeInTheDocument();
    expect(screen.getByText("raw bytes withheld")).toBeInTheDocument();
    expect(screen.getByText(/Metadata detail only/i)).toBeInTheDocument();
  });

  it("renders graph context as a bounded, provenance-bearing accessible list", () => {
    render(<QueryProvider><ProductSurface initialSurface="findings" initialId="FND-PREV-015" /></QueryProvider>);
    expect(screen.getByRole("heading", { name: "Affected path" })).toBeInTheDocument();
    expect(screen.getByText(/browser does not infer edges/i)).toBeInTheDocument();
    expect(screen.getByText("immutable repository snapshot")).toBeInTheDocument();
    expect(screen.getByText(/evidence linkage/i)).toBeInTheDocument();
  });
});

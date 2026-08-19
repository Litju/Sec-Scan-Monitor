import { notFound } from "next/navigation";
import { ProductSurface } from "@/components/firm/ProductSurface";
import { isSurfaceKey, type SurfaceKey } from "@/lib/domain/navigation";

export default async function SurfacePage({ params }: { params: Promise<{ surface: string }> }) {
  const { surface } = await params;
  if (!isSurfaceKey(surface)) notFound();
  return <ProductSurface initialSurface={surface as SurfaceKey} />;
}

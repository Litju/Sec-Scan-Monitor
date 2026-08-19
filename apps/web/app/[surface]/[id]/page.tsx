import { notFound } from "next/navigation";
import { ProductSurface } from "@/components/firm/ProductSurface";
import { isSurfaceKey, type SurfaceKey } from "@/lib/domain/navigation";

export default async function SurfaceDetailPage({
  params,
}: {
  params: Promise<{ surface: string; id: string }>;
}) {
  const { surface, id } = await params;
  if (!isSurfaceKey(surface)) notFound();
  return <ProductSurface initialSurface={surface as SurfaceKey} initialId={id} />;
}

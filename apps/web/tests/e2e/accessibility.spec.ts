import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("signature surfaces have no serious or critical accessibility violations", async ({ page }) => {
  const routes = ["/", "/cases/ENG-PUBLIC-015", "/findings/FND-PREV-015", "/evidence/E-1181", "/approvals", "/settings"];

  for (const route of routes) {
    await page.goto(route);
    const results = await new AxeBuilder({ page }).analyze();
    const blockingViolations = results.violations.filter((violation) => ["critical", "serious"].includes(violation.impact ?? ""));
    expect(blockingViolations, `${route} has blocking accessibility violations`).toEqual([]);
  }

  await page.goto("/");
  await page.getByRole("button", { name: "Open search and ask" }).click();
  await page.getByRole("option", { name: /Ask SecScanMonitor/i }).click();
  const assistantResults = await new AxeBuilder({ page }).analyze();
  const assistantBlockingViolations = assistantResults.violations.filter((violation) => ["critical", "serious"].includes(violation.impact ?? ""));
  expect(assistantBlockingViolations, "grounded assistant has blocking accessibility violations").toEqual([]);
});

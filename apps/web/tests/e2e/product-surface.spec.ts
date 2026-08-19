import { expect, test } from "@playwright/test";

test("golden path keeps case context while moving from Today to finding to evidence", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Today" })).toBeVisible();
  await page.getByRole("button", { name: "Open search and ask" }).click();
  await page.getByRole("combobox", { name: /Search/ }).fill("FND-PREV-015");
  await page.getByRole("combobox", { name: /Search/ }).press("Enter");
  await expect(page.getByRole("heading", { name: "FND-PREV-015" })).toBeVisible();
  await page.getByRole("button", { name: /E-1181/ }).click();
  await expect(page.getByRole("heading", { name: "Evidence", exact: true })).toBeVisible();
  await expect(page.getByText(/Metadata detail only/i)).toBeVisible();
});

test("preview approval controls remain disabled", async ({ page }) => {
  await page.goto("/approvals");
  await expect(page.getByRole("button", { name: "Approve this action" })).toBeDisabled();
  await expect(page.getByText(/Preview · no mutations/i)).toBeVisible();
});

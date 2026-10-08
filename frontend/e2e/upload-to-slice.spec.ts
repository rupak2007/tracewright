import { expect, test } from "@playwright/test";

const CAPTURE = process.env["E2E_CAPTURE"];

test.skip(!CAPTURE, "set E2E_CAPTURE to a capture file (the repository ships none)");

test("upload a capture, open the top incident, read its evidence and download a packet slice", async ({ page }) => {
  await page.goto("/");
  await page.locator('input[type="file"]').setInputFiles(CAPTURE as string);

  // upload -> overview of the new investigation; the page polls until the analysis completes
  await expect(page).toHaveURL(/\/investigations\//);
  await expect(page.getByText("✔ completed")).toBeVisible({ timeout: 180_000 });

  // click 1: the top-ranked incident; its evidence is on that page (NFR-04: <= 3 clicks)
  const firstIncident = page.locator("tbody tr").first().getByRole("link");
  await expect(firstIncident).toBeVisible();
  await firstIncident.click();
  await expect(page.getByRole("heading", { name: /^Incident I-/ })).toBeVisible();
  await expect(page.getByRole("table", { name: /Evidence/ })).toBeVisible();
  await expect(page.locator("tr#E-1")).toBeVisible();

  // a citation chip moves focus to the cited evidence row
  await page.getByRole("button", { name: "Go to evidence E-1" }).first().click();
  await expect(page.locator("tr#E-1")).toBeFocused();

  // why it fired: a metric against its threshold
  await expect(page.getByText(/threshold \d/).first()).toBeVisible();

  // packet slice: create, wait, download
  await page.getByRole("button", { name: /Create packet slice/ }).first().click();
  const download = page.getByRole("button", { name: /Download slice/ }).first();
  await expect(download).toBeVisible({ timeout: 120_000 });
  const [saved] = await Promise.all([page.waitForEvent("download"), download.click()]);
  expect(saved.suggestedFilename()).toMatch(/^tracewright-slice-\d+\.pcap$/);
});

// Renders every SVG beside this script to a PNG at its own size, 800 pixels wide.
//   node docs/diagrams/render.mjs
// Playwright is not a dependency of this repository. Set PLAYWRIGHT to the
// index.mjs of any Playwright install, such as one from `npm i playwright`.
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const { chromium } = await import(process.env.PLAYWRIGHT ?? 'playwright');

const browser = await chromium.launch({ headless: true });
for (const file of readdirSync(here).filter((f) => f.endsWith('.svg')).sort()) {
  const svg = readFileSync(join(here, file), 'utf8');
  const width = Number(svg.match(/width="(\d+)"/)[1]);
  const height = Number(svg.match(/height="(\d+)"/)[1]);
  const page = await browser.newPage({ viewport: { width, height }, deviceScaleFactor: 1 });
  await page.setContent(`<html><body style="margin:0">${svg}</body></html>`);
  const out = join(here, file.replace(/\.svg$/, '.png'));
  await page.locator('svg').first().screenshot({ path: out });
  await page.close();
  console.log(out);
}
await browser.close();

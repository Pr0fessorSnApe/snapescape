/**
 * SNAPESCAPE Puppeteer Browser Engine
 * Created By: Pr0Fessor_SnApe
 */
const express = require('express');
const puppeteer = require('puppeteer');

const app = express();
app.use(express.json({ limit: '50mb' }));
const PORT = process.env.PUPPETEER_PORT || 3002;

async function analyze(url) {
  const browser = await puppeteer.launch({ headless: 'new', args: ['--no-sandbox'] });
  const page = await browser.newPage();
  await page.setUserAgent('SNAPESCAPE/1.0 (Authorized Security Scanner)');
  const result = { url, links: [], forms: [], cookies: [], screenshot: null, localStorage: {} };

  try {
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });
    result.title = await page.title();
    result.links = await page.$$eval('a[href]', els => els.map(e => e.href).slice(0, 100));
    result.forms = await page.$$eval('form', forms => forms.map(f => ({
      action: f.action, method: f.method,
      inputs: Array.from(f.querySelectorAll('input')).map(i => ({ name: i.name, type: i.type }))
    })));
    result.cookies = await page.cookies();
    result.localStorage = await page.evaluate(() => ({ ...localStorage }));
    const buf = await page.screenshot({ encoding: 'base64', fullPage: false });
    result.screenshot = buf;
  } catch (e) {
    result.error = e.message;
  }
  await browser.close();
  return result;
}

app.get('/health', (_, res) => res.json({ status: 'ok', engine: 'puppeteer' }));
app.post('/analyze', async (req, res) => {
  if (!req.body.url) return res.status(400).json({ error: 'url required' });
  res.json(await analyze(req.body.url));
});
app.post('/screenshot', async (req, res) => {
  const r = await analyze(req.body.url);
  res.json({ screenshot: r.screenshot, title: r.title });
});

app.listen(PORT, () => console.log(`SNAPESCAPE Puppeteer on :${PORT}`));

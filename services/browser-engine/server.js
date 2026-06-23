/**
 * SNAPESCAPE Browser Engine — Playwright-based DOM analysis and screenshots.
 * Created By: Pr0Fessor_SnApe
 */

const { chromium } = require('playwright');
const express = require('express');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(express.json());

const PORT = process.env.BROWSER_ENGINE_PORT || 3001;

async function analyzePage(url) {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    userAgent: 'SNAPESCAPE/0.1 (Authorized Security Scanner)',
    ignoreHTTPSErrors: true,
  });
  const page = await context.newPage();
  const result = {
    url,
    title: null,
    technologies: [],
    forms: [],
    scripts: [],
    links: [],
    cookies: [],
    screenshot: null,
    console_errors: [],
    dom_xss_sinks: [],
  };

  page.on('console', msg => {
    if (msg.type() === 'error') result.console_errors.push(msg.text());
  });

  try {
    const response = await page.goto(url, { waitUntil: 'networkidle', timeout: 30000 });
    result.status = response?.status() || 0;
    result.title = await page.title();

    result.forms = await page.evaluate(() =>
      Array.from(document.querySelectorAll('form')).map(f => ({
        action: f.action,
        method: f.method,
        inputs: Array.from(f.querySelectorAll('input,textarea,select')).map(i => ({
          name: i.name, type: i.type, id: i.id,
        })),
      }))
    );

    result.scripts = await page.evaluate(() =>
      Array.from(document.querySelectorAll('script[src]')).map(s => s.src).slice(0, 50)
    );

    result.links = await page.evaluate(() =>
      Array.from(document.querySelectorAll('a[href]')).map(a => a.href).slice(0, 100)
    );

    result.dom_xss_sinks = await page.evaluate(() => {
      const sinks = [];
      const patterns = ['innerHTML', 'document.write', 'eval(', 'setTimeout(', 'setInterval('];
      document.querySelectorAll('script:not([src])').forEach(s => {
        patterns.forEach(p => { if (s.textContent.includes(p)) sinks.push(p); });
      });
      return [...new Set(sinks)];
    });

    const cookies = await context.cookies();
    result.cookies = cookies.map(c => ({ name: c.name, secure: c.secure, httpOnly: c.httpOnly }));

    const screenshotBuf = await page.screenshot({ type: 'png', fullPage: false });
    result.screenshot = screenshotBuf.toString('base64');
  } catch (err) {
    result.error = err.message;
  } finally {
    await browser.close();
  }

  return result;
}

app.get('/health', (_, res) => res.json({ status: 'ok', engine: 'browser' }));

app.post('/analyze', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'url required' });
  const result = await analyzePage(url);
  res.json(result);
});

app.post('/screenshot', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'url required' });
  const result = await analyzePage(url);
  res.json({ url, screenshot: result.screenshot, title: result.title });
});

app.listen(PORT, () => {
  console.log(`SNAPESCAPE Browser Engine listening on :${PORT}`);
});

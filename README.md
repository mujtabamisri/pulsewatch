# PulseWatch v2 — local website monitoring and SEO audits

Cross-platform: Node.js 22+ on Windows, macOS, or Linux.

## Run

```bash
npm install
npm run dev
```

Open http://127.0.0.1:5173. On Windows PowerShell, `npm.cmd install` and `npm.cmd run dev` also work.

## Features

- Uptime and HTTP status monitoring, incidents, response history, CSV export
- Response statistics: average, min, max, P50/P95/P99 and error rate
- SSL certificate validation/expiry and DNS A/AAAA checks on demand
- On-demand SEO heuristic audit with 11 checks and specific fixes, saved audit history
- PDF report with monitoring statistics and recent incidents
- Optional browser desktop notifications for newly detected failures (requires browser open and permission)

## Important limits

- This is a local development application, not a secured public multi-user SaaS. Do not expose the API to the public internet.
- Browser notifications require the dashboard open; they are not email/push alerts.
- The SEO score is PulseWatch's own heuristic score, **not** Google Lighthouse SEO. It cannot guarantee a Lighthouse score of 100.
- HTML checks do not execute client-side JavaScript, crawl the full site, or measure Core Web Vitals.
- Monitoring runs only while the Node server is running.
- Checks use a public-host URL filter, but for production-grade SSRF protection use network egress controls and DNS pinning.
- Data is stored in `data/pulsewatch.sqlite` and preserved when upgrading; back it up first.

# PulseWatch — Complete local edition

## Requirements
Node.js 22 or newer, npm, a modern browser, and an internet connection for installation and website checks. Works on Windows, macOS and Linux.

## Installation
1. Extract this ZIP.
2. Open the `PulseWatch-Complete` folder in VS Code or a terminal.
3. Run `npm install` (`npm.cmd install` on Windows PowerShell if scripts are blocked).
4. Run `npm run dev` (`npm.cmd run dev` on Windows PowerShell).
5. Visit http://127.0.0.1:5173

## What is included
- Website uptime and HTTP status monitoring; timeouts, failures and incident tracking.
- SSL certificate expiry and DNS A/AAAA diagnostics.
- Response-time charts and statistics (P50/P95/P99).
- On-demand page SEO audit with actionable fixes and saved history.
- Browser desktop notifications while the dashboard is open.
- CSV check history and PDF incident/performance reports.
- SQLite-compatible local persistence via sql.js (data/pulsewatch.sqlite).

## Important limitations
- SEO score is an 11-check PulseWatch heuristic, not an official Lighthouse score. It does not guarantee a 100 SEO result.
- No full-site crawler or Google Lighthouse integration in this release.
- No customizable API JSON assertions in this release.
- Monitoring works only while the Node backend is running.
- Local development use only. Do not expose the backend publicly without authentication and network safeguards.
- Site uptime percentage is based on completed checks, not continuous availability.

## Backing up existing data
Stop both servers. Copy `data/pulsewatch.sqlite` from the previous PulseWatch folder into this folder's `data/` directory, then restart.

## Troubleshooting
If the UI loads but API requests fail, check whether port 3000 is already in use and read backend terminal errors. If port 5173 is in use, close the other Vite instance. For cross-platform compatibility, use localhost on the same machine running the backend.

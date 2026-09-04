# DevInspect Security Auditor

A passive, production-quality automated web security auditing tool that analyzes web applications through the five major security-relevant surfaces exposed by Chromium DevTools: Elements, Sources, Network, Application, and Console.

## ⚠️ Authorized Use Only

**This tool is strictly for authorized security testing.**

DevInspect is a passive/low-impact security auditor. It does NOT:
- Attempt to bypass authentication
- Brute-force credentials
- Execute arbitrary attack payloads
- Modify requests to defeat authorization
- Perform destructive actions or denial-of-service testing

Its purpose is to identify security indicators from information already exposed to the browser. *It does not prove server-side authorization correctness by itself.*

## Architecture

DevInspect uses Playwright and Chromium to load target URLs and passively collect data. It follows a modular pipeline:

1. **Collection**: Captures data from DOM (Elements), JS/CSS (Sources), HTTP traffic (Network), client storage (Application), and runtime logs (Console).
2. **Analysis**: Runs robust keyword and regex scanners against the collected data to find PII, secrets, auth indicators, and misconfigurations.
3. **Correlation**: Cross-references evidence across multiple surfaces (e.g., finding an endpoint in JS, seeing it called in Network, and observing it return sensitive data).
4. **Risk Scoring**: Assigns severity and confidence to findings based on the correlated evidence.
5. **Reporting**: Generates Terminal, JSON, and HTML reports with safe redaction.

## Installation

Requires Node.js 18+.

```bash
# Install dependencies
npm install

# Install Playwright Chromium browser
npx playwright install chromium

# Compile TypeScript
npm run build
```

## CLI Usage

Run the scanner against an authorized target:

```bash
npm start -- "https://authorized-target.example/dashboard"
```

### Configuration Options

| Option | Default | Description |
|---|---|---|
| `--headless` | true | Run browser in headless mode (default) |
| `--headed` | false | Run browser with visible UI |
| `--timeout <ms>` | 30000 | Navigation timeout |
| `--network-idle-timeout <ms>` | 5000 | Wait time for network idle |
| `--wait <ms>` | 2000 | Additional stabilization delay |
| `--output <path>` | exposure_report.json | JSON report output path |
| `--html <path>` | exposure_report.html | HTML report output path |
| `--redaction <mode>` | safe | Redaction mode: `safe`, `balanced`, `forensic` |
| `--verbose` | false | Enable debug logging |

## Scan Lifecycle

1. **Launch**: Starts an isolated Chromium context.
2. **Navigate**: Loads the target URL and tracks redirects.
3. **Wait**: Waits for DOMContentLoaded, network idle, and stabilization.
4. **Collect**: Gathers data across all 5 DevTools surfaces.
5. **Analyze**: Runs keyword, regex, auth, storage, and endpoint analyzers.
6. **Correlate**: Evaluates evidence holistically.
7. **Report**: Outputs findings in requested formats.

## The Five DevTools Modules

- **Elements**: Inspects rendered HTML, forms, inputs, links, and hidden data.
- **Sources**: Captures loaded scripts and extracts API endpoints and suspicious comments.
- **Network**: Intercepts HTTP requests/responses, scanning bodies for sensitive data and checking security headers.
- **Application**: Analyzes Cookies, LocalStorage, SessionStorage for auth state and tokens.
- **Console**: Captures `console.log` and unhandled page errors for leaked data.

## Severity & Confidence Model

- **Severity** (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`): The potential impact if the finding is confirmed exploitable.
- **Confidence** (`HIGH`, `MEDIUM`, `LOW`): The tool's certainty based on observed evidence (e.g., higher if corroborated across multiple surfaces).

## Redaction Model

To protect sensitive data, DevInspect implements three redaction modes:
- **`safe`** (Default): Heavily masks values (e.g., `j***@example.com`, `***-**-1234`).
- **`balanced`**: Partially masks values, showing enough context for identification.
- **`forensic`**: Explicit opt-in only. Shows unmasked data in JSON/HTML (terminal is still partially masked).

## Testing

A local safe test server is included, containing only fake synthetic data.

```bash
# Run unit tests
npm test

# Run integration tests against the fake test server
npm run build
npm run test:server &
npm start -- "http://localhost:54321/internal/dashboard" --html test_report.html
```

## Limitations

- **Passive Nature**: DevInspect cannot determine if an endpoint is truly vulnerable to Broken Access Control; it only detects if the browser was able to access it.
- **Dynamic Content**: Heavy SPAs might require tuning the `--wait` parameter to ensure all content is loaded before collection.
- **Coverage**: The tool analyzes what the browser sees for a *single URL*. It is not a crawler.

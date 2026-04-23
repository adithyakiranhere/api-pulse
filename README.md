# 🔍 API Pulse — The Developer's API Swiss Army Knife

**Probe, benchmark, compare, and diagnose any API — from your terminal.**

One tool. Four modes. Zero fluff.

```
$ python api_pulse.py probe https://api.stripe.com
$ python api_pulse.py bench https://your-api.com/endpoint -n 200 -c 20
$ python api_pulse.py compare https://api.github.com https://api.gitlab.com
$ python api_pulse.py chain workflow.json
```

## Why this exists

Postman is bloated. `curl` gives you raw bytes. `wrk` only does load testing. `httpie` only does pretty requests. None of them do **all of this in one tool**:

| Feature | curl | httpie | wrk/hey | Postman | **API Pulse** |
|---|---|---|---|---|---|
| Single request with details | ✅ | ✅ | ❌ | ✅ | ✅ |
| TLS/SSL certificate inspection | ❌ | ❌ | ❌ | ❌ | ✅ |
| Security header audit + score | ❌ | ❌ | ❌ | ❌ | ✅ |
| Concurrent benchmarking | ❌ | ❌ | ✅ | ❌ | ✅ |
| Latency percentiles (p95/p99) | ❌ | ❌ | ✅ | ❌ | ✅ |
| Side-by-side API comparison | ❌ | ❌ | ❌ | ❌ | ✅ |
| Multi-step chain workflows | ❌ | ❌ | ❌ | ✅ | ✅ |
| Variable extraction between steps | ❌ | ❌ | ❌ | ✅ | ✅ |
| Beautiful terminal output | ❌ | ✅ | ❌ | N/A | ✅ |
| Standalone HTML reports | ❌ | ❌ | ❌ | ❌ | ✅ |
| Latency grading (A+ to F) | ❌ | ❌ | ❌ | ❌ | ✅ |
| Zero config / instant start | ✅ | ✅ | ✅ | ❌ | ✅ |

## The Four Modes

### 1. 🔍 Probe — Deep-inspect any endpoint

```bash
python api_pulse.py probe https://api.github.com
```

One request. Full X-ray. You get:
- Response status, latency, size
- Important response headers
- TLS certificate details (issuer, cipher, days until expiry)
- Security header audit with a 0-100 score
- Missing security headers flagged by severity (high/medium/low)

Add `--html report.html` to generate a shareable visual report.

### 2. ⚡ Bench — Stress-test with stats

```bash
python api_pulse.py bench https://your-api.com/endpoint -n 200 -c 20
```

Fire 200 requests with 20 concurrent workers. You get:
- Average, median, p95, p99, min, max latency
- Standard deviation (consistency)
- Requests per second
- Status code distribution with visual bars
- ASCII latency histogram
- A letter grade (A+ to F)

### 3. 🔀 Compare — Race endpoints head-to-head

```bash
python api_pulse.py compare https://api.github.com https://api.gitlab.com https://api.bitbucket.org
```

Benchmarks each endpoint with the same parameters and shows a side-by-side comparison table with the winner marked for each metric. Great for:
- Choosing between API providers
- Comparing your staging vs production
- Testing regional endpoints (US vs EU vs APAC)

### 4. 🔗 Chain — Multi-step API workflows

```bash
python api_pulse.py chain examples/chain_workflow.json -v
```

Run a sequence of API calls where each step can extract values and pass them to the next. Define workflows in simple JSON:

```json
[
  {
    "name": "Create user",
    "url": "https://api.example.com/users",
    "method": "POST",
    "body": "{\"name\": \"Jane\"}",
    "extract": { "user_id": "$.id" }
  },
  {
    "name": "Get created user",
    "url": "https://api.example.com/users/{{user_id}}",
    "method": "GET"
  }
]
```

Use cases: testing auth flows, signup → verify → login chains, CRUD lifecycle tests, webhook simulation.

## Install

```bash
git clone https://github.com/adithyakiranhere/api-pulse.git
cd api-pulse
pip install -r requirements.txt
```

Only dependency is `rich` for terminal output. Core HTTP engine uses Python's stdlib (`urllib`) — no `requests` needed.

## HTML Reports

Add `--html report.html` to `probe` or `bench` commands to generate a gorgeous standalone HTML report. No server needed — just open the file in any browser.

```bash
python api_pulse.py probe https://api.stripe.com --html stripe-report.html
python api_pulse.py bench https://your-api.com -n 100 --html bench-report.html
```

## Security Header Audit

The probe mode checks for 7 critical security headers and scores your API:

| Header | Severity | What it prevents |
|---|---|---|
| Strict-Transport-Security (HSTS) | 🔴 High | Downgrade attacks |
| Content-Security-Policy (CSP) | 🔴 High | XSS and injection |
| X-Content-Type-Options | 🟡 Medium | MIME sniffing |
| X-Frame-Options | 🟡 Medium | Clickjacking |
| Permissions-Policy | 🟡 Medium | Browser feature abuse |
| X-XSS-Protection | ⚪ Low | Legacy XSS (use CSP instead) |
| Referrer-Policy | ⚪ Low | Referrer leakage |

Score weights: High = 25pts, Medium = 15pts, Low = 10pts. Perfect = 100/100.

## Latency Grades

| Grade | Avg Latency | Verdict |
|---|---|---|
| A+ | < 100ms | Blazing fast |
| A | < 200ms | Excellent |
| B | < 500ms | Good |
| C | < 1000ms | Needs work |
| D | < 3000ms | Slow |
| F | > 3000ms | Critical |

## Use Cases

- **Before deploying**: probe your API to catch missing security headers
- **During development**: benchmark to find performance regressions
- **Choosing providers**: compare competing API services head-to-head
- **Testing workflows**: chain multi-step flows (auth → CRUD → cleanup)
- **Incident response**: quick probe to check if an API is responding and how fast
- **CI/CD integration**: run benchmarks in pipelines, fail on grade drops

## Ideas for contributions

- Export benchmark results to JSON/CSV for data analysis
- WebSocket support for real-time API testing
- GraphQL query support
- Authentication helpers (OAuth2, API keys, JWT)
- CI mode with exit codes based on latency thresholds
- Watch mode — continuously probe and alert on degradation
- Compare results over time (save + diff benchmarks)
- Request body templating with Faker-generated data

## License

MIT

---

*Built because every developer deserves better than `curl -v | grep` and a prayer.* 🔍

# WebApp Audit

Security scanner for web applications. Performs non-invasive security checks using a headless browser to bypass bot protection, and generates AI-friendly markdown reports.

## Features

- **Headless Browser Scanning** - Uses Puppeteer to bypass JS challenges and bot protection
- **Security Headers Analysis** - Checks for CSP, HSTS, X-Frame-Options, etc.
- **Exposed Files Detection** - Scans for .env, .git, config files, backups
- **Secret Detection** - Finds API keys, tokens, connection strings in responses
- **CORS Misconfiguration** - Detects overly permissive CORS policies
- **Cookie Security** - Validates HttpOnly, Secure, SameSite flags
- **API Security** - Checks for exposed admin/debug endpoints
- **Framework Detection** - Special checks for Next.js applications

## Installation

```bash
# Clone and install
git clone https://github.com/officialbubies/webapp-audit.git
cd webapp-audit
npm install

# Link globally (optional)
npm link
```

## Usage

```bash
# Basic scan
vibe-scan https://your-app.com

# Save AI-friendly report
vibe-scan https://your-app.com --output report.md

# JSON output for automation
vibe-scan https://your-app.com --json

# Custom timeout (in ms)
vibe-scan https://your-app.com --timeout 30000
```

## Example Output

```
🛡️  WebApp Audit v1.0.0

Target: https://example.com

📊 Security Score: 85/100 (A)
   Scanned: https://example.com
   Time: 3234ms

📋 Findings Summary:
   🟠 High: 1

─────────────────────────────────────────

 HIGH  Weak content-security-policy
   Category: headers
   CSP contains 'unsafe-inline' in script-src
   Fix: Add a Content-Security-Policy header to your server responses.
```

## AI-Friendly Reports

The `--output report.md` flag generates a markdown file optimized for AI consumption:

```markdown
# Security Scan Report

**Target:** https://example.com
**Score:** 85/100 (A)

## Findings

> **AI Assistant Instructions:** Each finding below includes a severity level,
> description, and fix. Apply fixes in order of severity (critical first).

### Security Headers

#### HIGH: Weak content-security-policy

**Description:** CSP contains 'unsafe-inline' in script-src

**Fix:** Remove 'unsafe-inline' from script-src if possible, or use nonces/hashes.
```

## What It Checks

### Security Headers
| Header | Severity | Description |
|--------|----------|-------------|
| Content-Security-Policy | High | Prevents XSS attacks |
| Strict-Transport-Security | High | Forces HTTPS |
| X-Frame-Options | Medium | Prevents clickjacking |
| X-Content-Type-Options | Medium | Prevents MIME sniffing |
| Referrer-Policy | Low | Controls referrer info |
| Permissions-Policy | Low | Controls browser features |

### Exposed Files
- `.env`, `.env.local`, `.env.production`
- `.git/config`, `.git/HEAD`
- `config.js`, `config.json`
- Database backups (`.sql` files)
- Debug logs

### Secrets Detection
- AWS Access Keys
- Stripe API Keys
- GitHub Tokens
- JWT Tokens
- Database Connection Strings
- Private Keys

### Cookie Security
- HttpOnly flag
- Secure flag
- SameSite attribute

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No high/critical findings |
| 1 | High severity findings |
| 2 | Critical severity findings |

## CI/CD Integration

```yaml
# GitHub Actions
- name: Security Scan
  run: |
    npx webapp-audit https://staging.your-app.com --json > security-report.json
    if [ $? -eq 2 ]; then
      echo "Critical vulnerabilities found!"
      exit 1
    fi
```

## Why Puppeteer?

Many modern hosting platforms (Vercel, Cloudflare, etc.) use JavaScript challenges to block automated requests. Traditional HTTP-based scanners get blocked and can't see your actual security headers. WebApp Audit uses a real browser engine to:

- Pass JavaScript challenges and bot protection
- See the actual headers your users see
- Detect client-side security issues
- Accurately assess your security posture

## Limitations

- External scanning only (no source code access)
- Requires Chrome/Chromium to be available
- Some checks may trigger WAF/security systems

## Contributing

PRs welcome! Areas for improvement:
- [ ] Add more framework-specific checks (Nuxt, SvelteKit, Remix)
- [ ] Add authentication support for scanning protected pages
- [ ] Add configuration file support
- [ ] Add parallel scanning for multiple URLs

## License

MIT

# Vibe Scanner 🔍

Security scanner for vibe-coded apps. Performs non-invasive security checks and generates AI-friendly markdown reports that can be fed directly to Claude, ChatGPT, or Cursor to fix vulnerabilities.

## Features

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
git clone https://github.com/yourusername/vibe-scanner.git
cd vibe-scanner
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

# Deep scan with headless browser (coming soon)
vibe-scan https://your-app.com --deep
```

## Example Output

```
🔍 Vibe App Scanner v1.0.0

Target: https://example.com

📊 Security Score: 65/100 (C)
   Scanned: https://example.com
   Time: 1234ms

📋 Findings Summary:
   🟠 High: 2
   🟡 Medium: 3
   🟢 Low: 1

─────────────────────────────────────────

 HIGH  Missing Content-Security-Policy
   Category: headers
   CSP helps prevent XSS attacks by controlling which resources can be loaded.
   Fix: Add a Content-Security-Policy header to your server responses.

 HIGH  Auth Cookie Missing HttpOnly: session
   Category: cookies
   Authentication cookies should have HttpOnly flag to prevent XSS theft.
   Fix: Add HttpOnly flag to the session cookie.
```

## AI-Friendly Reports

The `--output report.md` flag generates a markdown file optimized for AI consumption:

```markdown
# Security Scan Report

**Target:** https://example.com
**Score:** 65/100 (C)

## Findings

> **AI Assistant Instructions:** Each finding below includes a severity level, 
> description, and fix. Apply fixes in order of severity (critical first).

### 🛡️ Security Headers

#### 🟠 HIGH: Missing Content-Security-Policy

**Description:** CSP helps prevent XSS attacks...

**Fix:** Add a Content-Security-Policy header...

**Implementation:**

\`\`\`javascript
// Next.js (next.config.js)
async headers() {
  return [{
    source: '/:path*',
    headers: [{
      key: 'Content-Security-Policy',
      value: "default-src 'self'..."
    }]
  }]
}
\`\`\`
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
    npm install -g vibe-scanner
    vibe-scan https://staging.your-app.com --json > security-report.json
    if [ $? -eq 2 ]; then
      echo "Critical vulnerabilities found!"
      exit 1
    fi
```

## Limitations

- External scanning only (no source code access)
- Cannot detect all client-side issues without headless browser
- Rate-limited to avoid overwhelming target servers
- Some checks may trigger WAF/security systems

## Contributing

PRs welcome! Areas for improvement:
- [ ] Add Puppeteer for deep client-side scanning
- [ ] Add more framework-specific checks (Nuxt, SvelteKit, etc.)
- [ ] Add authentication support for scanning protected pages
- [ ] Add configuration file support (.vibescanrc)

## License

MIT

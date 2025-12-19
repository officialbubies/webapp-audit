# Security Scan Report

**Target:** https://app.gambino.gold  
**Score:** 70/100 (B)  
**Scan Time:** 2536ms  
**Date:** 2025-12-19T15:36:26.161Z

---

## Summary

| Severity | Count |
|----------|-------|
| 🟠 High | 2 |

---

## Findings

> **AI Assistant Instructions:** Each finding below includes a severity level, description, and fix. Apply fixes in order of severity (critical first). Code snippets are provided where applicable.

### 🛡️ Security Headers

#### 🟠 HIGH: Missing Content-Security-Policy

**Description:** CSP helps prevent XSS attacks by controlling which resources can be loaded.

**Fix:** Add a Content-Security-Policy header to your server responses.

**Implementation:**

```javascript
// Next.js (next.config.js)
async headers() {
  return [{
    source: '/:path*',
    headers: [{
      key: 'Content-Security-Policy',
      value: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    }]
  }]
}

// Express.js
app.use(helmet.contentSecurityPolicy({
  directives: { defaultSrc: ["'self'"] }
}));
```

---

#### 🟠 HIGH: Missing Strict-Transport-Security (HSTS)

**Description:** HSTS ensures browsers only connect via HTTPS.

**Fix:** Add Strict-Transport-Security header with max-age of at least 31536000.

**Implementation:**

```javascript
// Next.js (next.config.js)
headers: [{
  key: 'Strict-Transport-Security',
  value: 'max-age=31536000; includeSubDomains; preload'
}]

// Express.js
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));
```

---

---

## Quick Fixes

Here are the most impactful fixes to apply immediately:

1. **Missing Content-Security-Policy**: Add a Content-Security-Policy header to your server responses.
2. **Missing Strict-Transport-Security (HSTS)**: Add Strict-Transport-Security header with max-age of at least 31536000.

---

## Framework-Specific Recommendations

### Next.js Security Headers

Add this to your `next.config.js`:

```javascript
const securityHeaders = [
  {
    key: 'Content-Security-Policy',
    value: "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:;"
  },
  {
    key: 'Strict-Transport-Security',
    value: 'max-age=31536000; includeSubDomains; preload'
  },
  {
    key: 'X-Frame-Options',
    value: 'DENY'
  },
  {
    key: 'X-Content-Type-Options',
    value: 'nosniff'
  },
  {
    key: 'Referrer-Policy',
    value: 'strict-origin-when-cross-origin'
  },
  {
    key: 'Permissions-Policy',
    value: 'camera=(), microphone=(), geolocation=()'
  }
];

module.exports = {
  async headers() {
    return [
      {
        source: '/:path*',
        headers: securityHeaders,
      },
    ];
  },
};
```

### Express.js with Helmet

```javascript
const helmet = require('helmet');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

app.disable('x-powered-by');
```


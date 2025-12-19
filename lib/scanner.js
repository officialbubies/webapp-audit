const axios = require('axios');
const puppeteer = require('puppeteer');
const { URL } = require('url');

// Security header requirements (based on Mozilla Observatory)
const SECURITY_HEADERS = {
  'content-security-policy': {
    required: true,
    severity: 'high',
    title: 'Missing Content-Security-Policy',
    description: 'CSP helps prevent XSS attacks by controlling which resources can be loaded.',
    fix: 'Add a Content-Security-Policy header to your server responses.',
    validate: (value) => {
      if (!value) return false;
      // Check for unsafe-inline in script-src (bad)
      if (value.includes("'unsafe-inline'") && value.includes('script-src')) {
        return { valid: false, warning: "CSP contains 'unsafe-inline' in script-src" };
      }
      return { valid: true };
    }
  },
  'strict-transport-security': {
    required: true,
    severity: 'high',
    title: 'Missing Strict-Transport-Security (HSTS)',
    description: 'HSTS ensures browsers only connect via HTTPS.',
    fix: 'Add Strict-Transport-Security header with max-age of at least 31536000.',
    validate: (value) => {
      if (!value) return false;
      const maxAgeMatch = value.match(/max-age=(\d+)/);
      if (!maxAgeMatch) return { valid: false, warning: 'HSTS missing max-age' };
      const maxAge = parseInt(maxAgeMatch[1]);
      if (maxAge < 31536000) {
        return { valid: false, warning: `HSTS max-age too short (${maxAge}s, need 31536000s)` };
      }
      return { valid: true, bonus: value.includes('includeSubDomains') };
    }
  },
  'x-frame-options': {
    required: true,
    severity: 'medium',
    title: 'Missing X-Frame-Options',
    description: 'Prevents clickjacking attacks by controlling iframe embedding.',
    fix: "Add X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN",
    validate: (value) => {
      if (!value) return false;
      const valid = ['DENY', 'SAMEORIGIN'].includes(value.toUpperCase());
      return { valid };
    }
  },
  'x-content-type-options': {
    required: true,
    severity: 'medium',
    title: 'Missing X-Content-Type-Options',
    description: 'Prevents MIME type sniffing attacks.',
    fix: 'Add X-Content-Type-Options: nosniff',
    validate: (value) => ({ valid: value?.toLowerCase() === 'nosniff' })
  },
  'referrer-policy': {
    required: true,
    severity: 'low',
    title: 'Missing Referrer-Policy',
    description: 'Controls how much referrer information is sent with requests.',
    fix: 'Add Referrer-Policy: strict-origin-when-cross-origin',
    validate: (value) => {
      const validPolicies = [
        'no-referrer', 'no-referrer-when-downgrade', 'origin',
        'origin-when-cross-origin', 'same-origin', 'strict-origin',
        'strict-origin-when-cross-origin'
      ];
      return { valid: value && validPolicies.includes(value.toLowerCase()) };
    }
  },
  'permissions-policy': {
    required: false,
    severity: 'low',
    title: 'Missing Permissions-Policy',
    description: 'Controls which browser features can be used.',
    fix: 'Add Permissions-Policy header to restrict unnecessary browser features.',
    validate: (value) => ({ valid: !!value })
  },
  'x-xss-protection': {
    required: false,
    severity: 'info',
    title: 'X-XSS-Protection Header Present',
    description: 'This header is deprecated. Modern browsers ignore it in favor of CSP.',
    validate: (value) => {
      // Having this isn't bad, but it's not needed with CSP
      return { valid: true, info: value ? 'Deprecated but harmless' : null };
    }
  }
};

// Sensitive files to check for exposure
const EXPOSED_PATHS = [
  { path: '/.env', severity: 'critical', title: 'Exposed .env file' },
  { path: '/.env.local', severity: 'critical', title: 'Exposed .env.local file' },
  { path: '/.env.production', severity: 'critical', title: 'Exposed .env.production file' },
  { path: '/.git/config', severity: 'critical', title: 'Exposed .git directory' },
  { path: '/.git/HEAD', severity: 'critical', title: 'Exposed .git directory' },
  { path: '/config.js', severity: 'high', title: 'Exposed config.js' },
  { path: '/config.json', severity: 'high', title: 'Exposed config.json' },
  { path: '/.aws/credentials', severity: 'critical', title: 'Exposed AWS credentials' },
  { path: '/wp-config.php', severity: 'critical', title: 'Exposed WordPress config' },
  { path: '/phpinfo.php', severity: 'medium', title: 'Exposed phpinfo' },
  { path: '/.htpasswd', severity: 'critical', title: 'Exposed htpasswd file' },
  { path: '/server.js', severity: 'medium', title: 'Exposed server source' },
  { path: '/package.json', severity: 'low', title: 'Exposed package.json' },
  { path: '/.npmrc', severity: 'high', title: 'Exposed npm config (may contain tokens)' },
  { path: '/docker-compose.yml', severity: 'medium', title: 'Exposed Docker config' },
  { path: '/Dockerfile', severity: 'low', title: 'Exposed Dockerfile' },
  { path: '/backup.sql', severity: 'critical', title: 'Exposed database backup' },
  { path: '/database.sql', severity: 'critical', title: 'Exposed database dump' },
  { path: '/dump.sql', severity: 'critical', title: 'Exposed database dump' },
  { path: '/.DS_Store', severity: 'low', title: 'Exposed macOS metadata' },
  { path: '/debug.log', severity: 'medium', title: 'Exposed debug log' },
  { path: '/error.log', severity: 'medium', title: 'Exposed error log' },
  { path: '/npm-debug.log', severity: 'low', title: 'Exposed npm debug log' },
];

// API endpoints that shouldn't be publicly accessible
const SENSITIVE_ENDPOINTS = [
  { path: '/api/admin', severity: 'high', title: 'Admin API exposed without auth check' },
  { path: '/graphql', severity: 'medium', title: 'GraphQL endpoint (check introspection)' },
  { path: '/api/debug', severity: 'high', title: 'Debug endpoint exposed' },
  { path: '/api/test', severity: 'medium', title: 'Test endpoint exposed' },
  { path: '/api/internal', severity: 'high', title: 'Internal API exposed' },
  { path: '/_next/static/chunks/app', severity: 'info', title: 'Next.js app chunks exposed (normal but check for secrets)' },
];

// Patterns that indicate secrets in response bodies
const SECRET_PATTERNS = [
  { pattern: /sk[-_]live[-_][a-zA-Z0-9]{20,}/g, name: 'Stripe Live Key' },
  { pattern: /sk[-_]test[-_][a-zA-Z0-9]{20,}/g, name: 'Stripe Test Key' },
  { pattern: /AKIA[0-9A-Z]{16}/g, name: 'AWS Access Key' },
  { pattern: /ghp_[a-zA-Z0-9]{36}/g, name: 'GitHub Personal Access Token' },
  { pattern: /github_pat_[a-zA-Z0-9_]{22,}/g, name: 'GitHub PAT' },
  { pattern: /xox[baprs]-[0-9a-zA-Z-]{10,}/g, name: 'Slack Token' },
  { pattern: /-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/g, name: 'Private Key' },
  { pattern: /mongodb(\+srv)?:\/\/[^\s"']+/g, name: 'MongoDB Connection String' },
  { pattern: /postgres(ql)?:\/\/[^\s"']+/g, name: 'PostgreSQL Connection String' },
  { pattern: /mysql:\/\/[^\s"']+/g, name: 'MySQL Connection String' },
  { pattern: /redis:\/\/[^\s"']+/g, name: 'Redis Connection String' },
  { pattern: /Bearer\s+[a-zA-Z0-9\-_.]+\.[a-zA-Z0-9\-_.]+\.[a-zA-Z0-9\-_.]+/g, name: 'JWT Token' },
  { pattern: /api[_-]?key['":\s]*[=:]\s*['"]?[a-zA-Z0-9]{20,}['"]?/gi, name: 'API Key' },
  { pattern: /secret['":\s]*[=:]\s*['"]?[a-zA-Z0-9]{20,}['"]?/gi, name: 'Secret Value' },
];

async function scanUrl(url, options = {}) {
  const startTime = Date.now();
  const findings = [];
  const { timeout = 10000, deep = false } = options;

  const axiosConfig = {
    timeout,
    validateStatus: () => true, // Don't throw on any status
    maxRedirects: 5,
    headers: {
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.5'
    }
  };

  // 1. Use Puppeteer to get headers (passes JS challenges)
  let browser;
  let headers = {};
  let responseBody = '';
  let response = { data: '', headers: {} };

  try {
    browser = await puppeteer.launch({
      headless: 'new',
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });

    const page = await browser.newPage();

    // Navigate and wait for page load
    const puppeteerResponse = await page.goto(url, {
      waitUntil: 'networkidle2',
      timeout: timeout
    });

    // Get headers from response (lowercase keys for consistency)
    if (puppeteerResponse) {
      const rawHeaders = puppeteerResponse.headers();
      for (const [key, value] of Object.entries(rawHeaders)) {
        headers[key.toLowerCase()] = value;
      }
    }

    // Get page content
    responseBody = await page.content();
    response = { data: responseBody, headers };

    await browser.close();
  } catch (error) {
    if (browser) await browser.close();
    throw new Error(`Failed to connect to ${url}: ${error.message}`);
  }
  
  // 2. Check security headers
  await checkSecurityHeaders(headers, findings);
  
  // 3. Check for exposed sensitive files
  await checkExposedFiles(url, axiosConfig, findings);
  
  // 4. Check for secrets in main page source
  checkSecretsInResponse(response.data, url, findings);
  
  // 5. Check CORS configuration
  await checkCors(url, axiosConfig, findings);
  
  // 6. Check cookies security
  checkCookies(headers, findings);
  
  // 7. Check for common misconfigurations
  await checkMisconfigurations(url, response, axiosConfig, findings);
  
  // 8. If Next.js, check for specific issues
  if (isNextJs(response)) {
    await checkNextJsIssues(url, axiosConfig, findings);
  }
  
  // 9. Check sensitive API endpoints
  await checkSensitiveEndpoints(url, axiosConfig, findings);
  
  // Calculate score
  const score = calculateScore(findings);
  
  return {
    url,
    findings,
    score,
    scanTime: Date.now() - startTime,
    headersChecked: Object.keys(SECURITY_HEADERS).length,
    pathsChecked: EXPOSED_PATHS.length,
    timestamp: new Date().toISOString()
  };
}

async function checkSecurityHeaders(headers, findings) {
  for (const [headerName, config] of Object.entries(SECURITY_HEADERS)) {
    const value = headers[headerName];
    const validation = config.validate(value);
    
    if (!value && config.required) {
      findings.push({
        severity: config.severity,
        category: 'headers',
        title: config.title,
        description: config.description,
        fix: config.fix,
        code: getHeaderFixCode(headerName)
      });
    } else if (value && validation && !validation.valid) {
      findings.push({
        severity: config.severity,
        category: 'headers',
        title: `Weak ${headerName}`,
        description: validation.warning || config.description,
        fix: config.fix,
        current: value
      });
    }
  }
}

async function checkExposedFiles(baseUrl, axiosConfig, findings) {
  const checks = EXPOSED_PATHS.map(async ({ path, severity, title }) => {
    try {
      const url = new URL(path, baseUrl).toString();
      const response = await axios.get(url, { 
        ...axiosConfig, 
        timeout: 5000,
        maxContentLength: 1024 * 10 // Only download first 10KB
      });
      
      // Check if it returned actual content (not a custom 404 page)
      if (response.status === 200) {
        const contentType = response.headers['content-type'] || '';
        const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
        
        // Verify it's not just a redirect or error page
        if (!body.includes('<!DOCTYPE') && !body.includes('Page Not Found') && 
            !body.includes('404') && body.length > 0) {
          findings.push({
            severity,
            category: 'exposure',
            title,
            description: `Sensitive file accessible at ${path}`,
            fix: `Block access to ${path} in your web server configuration.`,
            url: url
          });
          
          // Also check for secrets in the exposed file
          checkSecretsInResponse(body, url, findings);
        }
      }
    } catch (error) {
      // 404 or timeout is fine
    }
  });
  
  await Promise.all(checks);
}

function checkSecretsInResponse(body, url, findings) {
  if (typeof body !== 'string') return;
  
  for (const { pattern, name } of SECRET_PATTERNS) {
    const matches = body.match(pattern);
    if (matches) {
      findings.push({
        severity: 'critical',
        category: 'secrets',
        title: `Exposed ${name}`,
        description: `Found what appears to be a ${name} in the response from ${url}`,
        fix: `Remove secrets from client-side code. Use environment variables and server-side only.`,
        evidence: matches[0].substring(0, 20) + '...' // Truncate for safety
      });
    }
  }
}

async function checkCors(baseUrl, axiosConfig, findings) {
  try {
    // Test with a malicious origin
    const response = await axios.options(baseUrl, {
      ...axiosConfig,
      headers: {
        ...axiosConfig.headers,
        'Origin': 'https://evil-attacker.com',
        'Access-Control-Request-Method': 'GET'
      }
    });
    
    const allowOrigin = response.headers['access-control-allow-origin'];
    const allowCredentials = response.headers['access-control-allow-credentials'];
    
    if (allowOrigin === '*') {
      findings.push({
        severity: 'medium',
        category: 'cors',
        title: 'CORS Allows All Origins',
        description: 'Access-Control-Allow-Origin is set to *, which allows any website to make requests.',
        fix: 'Restrict CORS to specific trusted origins.'
      });
    }
    
    if (allowOrigin === 'https://evil-attacker.com') {
      findings.push({
        severity: 'high',
        category: 'cors',
        title: 'CORS Reflects Origin',
        description: 'The server reflects the Origin header, allowing any site to make authenticated requests.',
        fix: 'Whitelist specific origins instead of reflecting the Origin header.'
      });
    }
    
    if (allowOrigin && allowCredentials === 'true' && allowOrigin !== 'null') {
      findings.push({
        severity: 'high',
        category: 'cors',
        title: 'CORS Allows Credentials with Wide Origin',
        description: 'CORS is configured to allow credentials with a permissive origin policy.',
        fix: 'Be restrictive with Access-Control-Allow-Credentials when using wide origin policies.'
      });
    }
  } catch (error) {
    // CORS check failed, probably fine
  }
}

function checkCookies(headers, findings) {
  const setCookies = headers['set-cookie'];
  if (!setCookies) return;
  
  const cookies = Array.isArray(setCookies) ? setCookies : [setCookies];
  
  for (const cookie of cookies) {
    const cookieName = cookie.split('=')[0];
    
    // Check for session/auth cookies without security flags
    const isAuthCookie = /session|token|auth|jwt|sid/i.test(cookieName);
    
    if (isAuthCookie) {
      if (!cookie.toLowerCase().includes('httponly')) {
        findings.push({
          severity: 'high',
          category: 'cookies',
          title: `Auth Cookie Missing HttpOnly: ${cookieName}`,
          description: 'Authentication cookies should have HttpOnly flag to prevent XSS theft.',
          fix: `Add HttpOnly flag to the ${cookieName} cookie.`
        });
      }
      
      if (!cookie.toLowerCase().includes('secure')) {
        findings.push({
          severity: 'high',
          category: 'cookies',
          title: `Auth Cookie Missing Secure Flag: ${cookieName}`,
          description: 'Authentication cookies should have Secure flag to prevent transmission over HTTP.',
          fix: `Add Secure flag to the ${cookieName} cookie.`
        });
      }
      
      if (!cookie.toLowerCase().includes('samesite')) {
        findings.push({
          severity: 'medium',
          category: 'cookies',
          title: `Auth Cookie Missing SameSite: ${cookieName}`,
          description: 'Authentication cookies should have SameSite attribute to prevent CSRF.',
          fix: `Add SameSite=Strict or SameSite=Lax to the ${cookieName} cookie.`
        });
      }
    }
  }
}

async function checkMisconfigurations(url, response, axiosConfig, findings) {
  const body = typeof response.data === 'string' ? response.data : '';
  
  // Check for source maps in production
  if (body.includes('//# sourceMappingURL=')) {
    findings.push({
      severity: 'medium',
      category: 'config',
      title: 'Source Maps Exposed',
      description: 'Source maps are included in production, exposing original source code.',
      fix: 'Disable source maps in production builds or restrict access to .map files.'
    });
  }
  
  // Check for debug mode indicators
  const debugIndicators = [
    'DEBUG=true', 'NODE_ENV=development', 'stack trace:', 
    'Traceback (most recent', 'at Object.<anonymous>'
  ];
  
  for (const indicator of debugIndicators) {
    if (body.includes(indicator)) {
      findings.push({
        severity: 'medium',
        category: 'config',
        title: 'Debug Mode Indicators Found',
        description: `Found "${indicator}" which may indicate debug mode is enabled.`,
        fix: 'Ensure production builds have debug mode disabled.'
      });
      break; // Only report once
    }
  }
  
  // Check server header for version disclosure
  const serverHeader = response.headers['server'];
  if (serverHeader && /[0-9]+\.[0-9]+/.test(serverHeader)) {
    findings.push({
      severity: 'low',
      category: 'disclosure',
      title: 'Server Version Disclosed',
      description: `Server header reveals version: ${serverHeader}`,
      fix: 'Remove or obscure the Server header to prevent version fingerprinting.'
    });
  }
  
  // Check X-Powered-By
  const poweredBy = response.headers['x-powered-by'];
  if (poweredBy) {
    findings.push({
      severity: 'low',
      category: 'disclosure',
      title: 'Technology Stack Disclosed',
      description: `X-Powered-By header reveals: ${poweredBy}`,
      fix: 'Remove the X-Powered-By header.',
      code: "app.disable('x-powered-by'); // Express.js"
    });
  }
}

function isNextJs(response) {
  const body = typeof response.data === 'string' ? response.data : '';
  return body.includes('/_next/') || 
         response.headers['x-nextjs-cache'] ||
         body.includes('__NEXT_DATA__');
}

async function checkNextJsIssues(baseUrl, axiosConfig, findings) {
  // Check for exposed _next/static with buildId
  try {
    const buildManifest = await axios.get(
      new URL('/_next/static/chunks/webpack.js', baseUrl).toString(),
      { ...axiosConfig, timeout: 5000 }
    );
    
    if (buildManifest.status === 200) {
      // Check for hardcoded secrets in webpack bundle
      checkSecretsInResponse(buildManifest.data, baseUrl + '/_next/static', findings);
    }
  } catch (error) {
    // Fine
  }
  
  // Check for exposed API routes that might have issues
  try {
    // Common Next.js API patterns
    const apiPaths = ['/api/auth/session', '/api/user', '/api/config'];
    
    for (const path of apiPaths) {
      const response = await axios.get(
        new URL(path, baseUrl).toString(),
        { ...axiosConfig, timeout: 3000 }
      );
      
      if (response.status === 200 && response.data) {
        const body = JSON.stringify(response.data);
        // Check if it returns sensitive data without auth
        if (body.includes('email') || body.includes('password') || 
            body.includes('token') || body.includes('secret')) {
          findings.push({
            severity: 'high',
            category: 'api',
            title: `Potentially Sensitive API Endpoint: ${path}`,
            description: 'API endpoint returns what may be sensitive data without authentication.',
            fix: 'Add authentication middleware to protect sensitive API endpoints.'
          });
        }
      }
    }
  } catch (error) {
    // Fine
  }
}

async function checkSensitiveEndpoints(baseUrl, axiosConfig, findings) {
  for (const { path, severity, title } of SENSITIVE_ENDPOINTS) {
    try {
      const url = new URL(path, baseUrl).toString();
      const response = await axios.get(url, { ...axiosConfig, timeout: 5000 });
      
      // 200 without auth redirect might be concerning
      if (response.status === 200 && !response.request?.res?.responseUrl?.includes('login')) {
        // For GraphQL, check if introspection is enabled
        if (path === '/graphql') {
          try {
            const introspection = await axios.post(url, {
              query: '{ __schema { types { name } } }'
            }, axiosConfig);
            
            if (introspection.status === 200 && introspection.data?.data?.__schema) {
              findings.push({
                severity: 'medium',
                category: 'api',
                title: 'GraphQL Introspection Enabled',
                description: 'GraphQL introspection is enabled, exposing your entire API schema.',
                fix: 'Disable introspection in production: https://www.apollographql.com/docs/apollo-server/api/apollo-server/#introspection'
              });
            }
          } catch (e) {}
        } else {
          findings.push({
            severity,
            category: 'api',
            title,
            description: `Endpoint ${path} appears to be accessible without authentication.`,
            fix: 'Ensure proper authentication is required for sensitive endpoints.'
          });
        }
      }
    } catch (error) {
      // Fine, endpoint not accessible
    }
  }
}

function getHeaderFixCode(headerName) {
  const fixes = {
    'content-security-policy': `// Next.js (next.config.js)
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
}));`,

    'strict-transport-security': `// Next.js (next.config.js)
headers: [{
  key: 'Strict-Transport-Security',
  value: 'max-age=31536000; includeSubDomains; preload'
}]

// Express.js
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));`,

    'x-frame-options': `// Next.js
headers: [{ key: 'X-Frame-Options', value: 'DENY' }]

// Express.js
app.use(helmet.frameguard({ action: 'deny' }));`,

    'x-content-type-options': `// Next.js
headers: [{ key: 'X-Content-Type-Options', value: 'nosniff' }]

// Express.js
app.use(helmet.noSniff());`,

    'referrer-policy': `// Next.js
headers: [{ key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' }]

// Express.js
app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));`
  };
  
  return fixes[headerName] || '';
}

function calculateScore(findings) {
  let score = 100;
  
  const deductions = {
    critical: 25,
    high: 15,
    medium: 8,
    low: 3,
    info: 0
  };
  
  for (const finding of findings) {
    score -= deductions[finding.severity] || 0;
  }
  
  return Math.max(0, score);
}

module.exports = { scanUrl };

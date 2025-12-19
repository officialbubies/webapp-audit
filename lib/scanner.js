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
  },
  'cross-origin-opener-policy': {
    required: true,
    severity: 'medium',
    title: 'Missing Cross-Origin-Opener-Policy (COOP)',
    description: 'COOP isolates your page from cross-origin windows, protecting against Spectre attacks and XS-Leaks.',
    fix: 'Add Cross-Origin-Opener-Policy: same-origin-allow-popups',
    validate: (value) => {
      if (!value) return false;
      const validPolicies = ['same-origin', 'same-origin-allow-popups', 'unsafe-none'];
      return { valid: validPolicies.includes(value.toLowerCase()) };
    }
  },
  'cross-origin-embedder-policy': {
    required: false,
    severity: 'low',
    title: 'Missing Cross-Origin-Embedder-Policy (COEP)',
    description: 'COEP enables cross-origin isolation when combined with COOP.',
    fix: 'Add Cross-Origin-Embedder-Policy: credentialless or require-corp',
    validate: (value) => {
      if (!value) return false;
      const validPolicies = ['require-corp', 'credentialless', 'unsafe-none'];
      return { valid: validPolicies.includes(value.toLowerCase()) };
    }
  },
  'cross-origin-resource-policy': {
    required: false,
    severity: 'low',
    title: 'Missing Cross-Origin-Resource-Policy (CORP)',
    description: 'CORP prevents other sites from loading your resources.',
    fix: 'Add Cross-Origin-Resource-Policy: same-origin',
    validate: (value) => {
      if (!value) return false;
      const validPolicies = ['same-origin', 'same-site', 'cross-origin'];
      return { valid: validPolicies.includes(value.toLowerCase()) };
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
  const { timeout = 30000, deep = false, verbose = null } = options;
  const log = verbose || (() => {}); // No-op if not verbose

  // Context object to track detected technologies for smarter findings
  const context = {
    framework: null,        // 'nextjs', 'react', 'vue', 'angular', etc.
    hosting: null,          // 'vercel', 'netlify', 'cloudflare', etc.
    hasExternalApi: false,
    apiHasProperCors: false
  };

  const axiosConfig = {
    timeout: Math.min(timeout, 15000), // Cap axios at 15s for secondary checks
    validateStatus: () => true,
    maxRedirects: 5,
    headers: {
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.5'
    }
  };

  // 1. Use Puppeteer to get headers (passes JS challenges)
  log('Launching headless browser...');
  let browser;
  let headers = {};
  let responseBody = '';
  let response = { data: '', headers: {} };

  try {
    browser = await puppeteer.launch({
      headless: 'new',
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--disable-gpu',
        '--window-size=1920,1080'
      ]
    });

    const page = await browser.newPage();

    // Set a realistic viewport and user agent
    await page.setViewport({ width: 1920, height: 1080 });
    await page.setUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

    // Navigate and wait for page load - try multiple strategies
    log(`Navigating to ${url}...`);
    let puppeteerResponse;
    try {
      puppeteerResponse = await page.goto(url, {
        waitUntil: 'networkidle2',
        timeout: timeout
      });
    } catch (navError) {
      // If networkidle2 times out, try with just domcontentloaded
      if (navError.message.includes('timeout')) {
        puppeteerResponse = await page.goto(url, {
          waitUntil: 'domcontentloaded',
          timeout: timeout
        });
      } else {
        throw navError;
      }
    }

    // Get headers from response (lowercase keys for consistency)
    log('Extracting response headers...');
    if (puppeteerResponse) {
      const rawHeaders = puppeteerResponse.headers();
      for (const [key, value] of Object.entries(rawHeaders)) {
        headers[key.toLowerCase()] = value;
      }
      log(`Found ${Object.keys(headers).length} headers`);
    }

    // Get page content
    responseBody = await page.content();
    response = { data: responseBody, headers };
    log(`Page loaded (${Math.round(responseBody.length / 1024)}KB)`);

    await browser.close();
    log('Browser closed');
  } catch (error) {
    if (browser) await browser.close();
    throw new Error(`Failed to connect to ${url}: ${error.message}`);
  }

  // Detect framework and hosting for context-aware findings
  detectTechnologies(response, headers, context);
  if (context.framework) log(`Detected framework: ${context.framework}`);
  if (context.hosting) log(`Detected hosting: ${context.hosting}`);

  // 2. Check security headers
  log('Checking security headers...');
  await checkSecurityHeaders(headers, findings, context);
  log(`Security headers: ${findings.length} issues found`);

  // 3. Check for exposed sensitive files
  log(`Checking ${EXPOSED_PATHS.length} sensitive file paths...`);
  const preExposedCount = findings.length;
  await checkExposedFiles(url, axiosConfig, findings);
  log(`Exposed files: ${findings.length - preExposedCount} issues found`);

  // 4. Check for secrets in main page source
  log('Scanning page source for secrets...');
  const preSecretsCount = findings.length;
  checkSecretsInResponse(response.data, url, findings);
  log(`Secrets scan: ${findings.length - preSecretsCount} issues found`);

  // 5. Check CORS configuration
  log('Testing CORS configuration...');
  const preCorsCount = findings.length;
  await checkCors(url, axiosConfig, findings, context);
  log(`CORS check: ${findings.length - preCorsCount} issues found`);

  // 6. Check cookies security
  log('Analyzing cookies...');
  const preCookiesCount = findings.length;
  checkCookies(headers, findings);
  log(`Cookie analysis: ${findings.length - preCookiesCount} issues found`);

  // 7. Check for common misconfigurations
  log('Checking for misconfigurations...');
  const preMisconfigCount = findings.length;
  await checkMisconfigurations(url, response, axiosConfig, findings);
  log(`Misconfig check: ${findings.length - preMisconfigCount} issues found`);

  // 8. If Next.js, check for specific issues
  if (isNextJs(response)) {
    log('Detected Next.js - running framework-specific checks...');
    const preNextCount = findings.length;
    await checkNextJsIssues(url, axiosConfig, findings);
    log(`Next.js check: ${findings.length - preNextCount} issues found`);
  }

  // 9. Check sensitive API endpoints
  log('Probing sensitive endpoints...');
  const preEndpointCount = findings.length;
  await checkSensitiveEndpoints(url, axiosConfig, findings);
  log(`Endpoint check: ${findings.length - preEndpointCount} issues found`);

  // 10. Detect and scan external APIs
  log('Detecting external APIs in page source...');
  const preApiCount = findings.length;
  await detectAndScanApis(url, response.data, axiosConfig, findings, log);
  log(`API scan: ${findings.length - preApiCount} issues found`);

  // Calculate score
  const score = calculateScore(findings);

  return {
    url,
    findings,
    score,
    scanTime: Date.now() - startTime,
    headersChecked: Object.keys(SECURITY_HEADERS).length,
    pathsChecked: EXPOSED_PATHS.length,
    timestamp: new Date().toISOString(),
    context // Include detected technologies
  };
}

function detectTechnologies(response, headers, context) {
  const body = typeof response.data === 'string' ? response.data : '';

  // Detect framework
  if (body.includes('/_next/') || headers['x-nextjs-cache'] || body.includes('__NEXT_DATA__')) {
    context.framework = 'nextjs';
  } else if (body.includes('ng-version') || body.includes('ng-app')) {
    context.framework = 'angular';
  } else if (body.includes('data-v-') || body.includes('__vue__')) {
    context.framework = 'vue';
  } else if (body.includes('data-reactroot') || body.includes('_reactRootContainer')) {
    context.framework = 'react';
  }

  // Detect hosting platform
  if (headers['x-vercel-id'] || headers['x-vercel-cache'] || headers['server']?.includes('Vercel')) {
    context.hosting = 'vercel';
  } else if (headers['x-nf-request-id'] || headers['server']?.includes('Netlify')) {
    context.hosting = 'netlify';
  } else if (headers['cf-ray'] || headers['server']?.includes('cloudflare')) {
    context.hosting = 'cloudflare';
  } else if (headers['x-amz-cf-id']) {
    context.hosting = 'aws-cloudfront';
  } else if (headers['x-github-request-id']) {
    context.hosting = 'github-pages';
  }
}

async function checkSecurityHeaders(headers, findings, context = {}) {
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
      // Add context for framework-specific issues
      let contextNote = null;
      let adjustedSeverity = config.severity;

      if (headerName === 'content-security-policy' && validation.warning?.includes('unsafe-inline')) {
        if (context.framework === 'nextjs') {
          contextNote = "⚠️ Context: Next.js requires 'unsafe-inline' for server-side rendering. This is expected behavior and cannot be removed without breaking the app. Consider using nonces if strict CSP is required.";
          adjustedSeverity = 'medium'; // Downgrade since it's expected
        } else if (context.framework === 'react' || context.framework === 'vue') {
          contextNote = "⚠️ Context: Many React/Vue apps need 'unsafe-inline' for CSS-in-JS libraries. Check if you can use nonces or hashes instead.";
        }
      }

      findings.push({
        severity: adjustedSeverity,
        category: 'headers',
        title: `Weak ${headerName}`,
        description: validation.warning || config.description,
        fix: config.fix,
        current: value,
        context: contextNote
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

async function checkCors(baseUrl, axiosConfig, findings, context = {}) {
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
      // Determine context-aware severity and explanation
      let contextNote = null;
      let adjustedSeverity = 'medium';

      if (context.hosting === 'vercel' || context.hosting === 'netlify' || context.hosting === 'cloudflare') {
        contextNote = `ℹ️ Context: This CORS header is coming from ${context.hosting}'s hosting layer, not your application code. For static frontend pages (HTML/JS/CSS), this is typically harmless since CORS protects APIs, not static assets. If your app has a separate API backend, check that the API has proper CORS restrictions - that's what matters for security.`;
        adjustedSeverity = 'low'; // Downgrade for frontend hosting
      }

      if (context.hasExternalApi && context.apiHasProperCors) {
        contextNote = (contextNote || '') + ` ✅ Your external API was detected and has proper CORS configuration.`;
        adjustedSeverity = 'info';
      }

      findings.push({
        severity: adjustedSeverity,
        category: 'cors',
        title: 'CORS Allows All Origins',
        description: 'Access-Control-Allow-Origin is set to *, which allows any website to make requests.',
        fix: context.hosting
          ? 'For frontend hosting, this is usually fine. Ensure your API backend has proper CORS restrictions.'
          : 'Restrict CORS to specific trusted origins.',
        context: contextNote
      });
    }

    if (allowOrigin === 'https://evil-attacker.com') {
      findings.push({
        severity: 'high',
        category: 'cors',
        title: 'CORS Reflects Origin',
        description: 'The server reflects the Origin header, allowing any site to make authenticated requests.',
        fix: 'Whitelist specific origins instead of reflecting the Origin header.',
        context: '🚨 This is a real security issue - the server echoes back any origin, which bypasses CORS protection entirely.'
      });
    }

    if (allowOrigin && allowCredentials === 'true' && allowOrigin !== 'null') {
      findings.push({
        severity: 'high',
        category: 'cors',
        title: 'CORS Allows Credentials with Wide Origin',
        description: 'CORS is configured to allow credentials with a permissive origin policy.',
        fix: 'Be restrictive with Access-Control-Allow-Credentials when using wide origin policies.',
        context: '🚨 This combination allows any site to make authenticated requests on behalf of your users.'
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

async function detectAndScanApis(baseUrl, body, axiosConfig, findings, log = () => {}) {
  if (typeof body !== 'string') return;

  // Patterns to detect API URLs in page source
  const apiPatterns = [
    // Environment variables in Next.js/React
    /NEXT_PUBLIC_API_URL['":\s]*['"]?(https?:\/\/[^'">\s]+)/gi,
    /REACT_APP_API_URL['":\s]*['"]?(https?:\/\/[^'">\s]+)/gi,
    /API_URL['":\s]*['"]?(https?:\/\/[^'">\s]+)/gi,
    /BACKEND_URL['":\s]*['"]?(https?:\/\/[^'">\s]+)/gi,
    // Direct API references
    /["'](https?:\/\/api\.[^'">\s]+)["']/gi,
    /["'](https?:\/\/[^'">\s]*\/api[^'">\s]*)["']/gi,
    // Common API patterns
    /baseURL['":\s]*['"]?(https?:\/\/[^'">\s]+)/gi,
    /apiEndpoint['":\s]*['"]?(https?:\/\/[^'">\s]+)/gi,
  ];

  const detectedApis = new Set();
  const baseUrlHost = new URL(baseUrl).hostname;

  for (const pattern of apiPatterns) {
    let match;
    while ((match = pattern.exec(body)) !== null) {
      const apiUrl = match[1];
      if (apiUrl && apiUrl.startsWith('http')) {
        try {
          const apiHost = new URL(apiUrl).hostname;
          // Only scan external APIs (different domain)
          if (apiHost !== baseUrlHost && !apiHost.includes('localhost')) {
            detectedApis.add(apiUrl.replace(/\/+$/, '')); // Remove trailing slashes
          }
        } catch (e) {}
      }
    }
  }

  // Scan each detected API
  if (detectedApis.size > 0) {
    log(`Found ${detectedApis.size} external API(s): ${[...detectedApis].map(u => new URL(u).hostname).join(', ')}`);
    for (const apiUrl of detectedApis) {
      log(`Scanning API: ${apiUrl}`);
      await scanApiEndpoint(apiUrl, axiosConfig, findings);
    }
  } else {
    log('No external APIs detected in page source');
  }
}

async function scanApiEndpoint(apiUrl, axiosConfig, findings) {
  const apiHost = new URL(apiUrl).hostname;

  try {
    // 1. Check API security headers
    const response = await axios.get(apiUrl, {
      ...axiosConfig,
      timeout: 10000,
      validateStatus: () => true
    });

    const headers = response.headers;

    // Check for missing security headers on API
    if (!headers['strict-transport-security']) {
      findings.push({
        severity: 'high',
        category: 'api-headers',
        title: `API Missing HSTS: ${apiHost}`,
        description: `The API at ${apiUrl} is missing Strict-Transport-Security header.`,
        fix: 'Add HSTS header to your API server.'
      });
    }

    // Check CORS on API
    const corsResponse = await axios.options(apiUrl, {
      ...axiosConfig,
      timeout: 5000,
      headers: {
        ...axiosConfig.headers,
        'Origin': 'https://evil-attacker.com',
        'Access-Control-Request-Method': 'GET'
      }
    });

    const allowOrigin = corsResponse.headers['access-control-allow-origin'];
    const allowCredentials = corsResponse.headers['access-control-allow-credentials'];

    if (allowOrigin === '*') {
      findings.push({
        severity: 'medium',
        category: 'api-cors',
        title: `API CORS Allows All Origins: ${apiHost}`,
        description: `The API at ${apiUrl} has Access-Control-Allow-Origin: *, allowing any website to make requests.`,
        fix: 'Restrict API CORS to specific trusted origins.'
      });
    }

    if (allowOrigin === 'https://evil-attacker.com') {
      findings.push({
        severity: 'high',
        category: 'api-cors',
        title: `API CORS Reflects Origin: ${apiHost}`,
        description: `The API at ${apiUrl} reflects the Origin header, allowing any site to make authenticated requests.`,
        fix: 'Whitelist specific origins instead of reflecting the Origin header.'
      });
    }

    if (allowCredentials === 'true' && (allowOrigin === '*' || allowOrigin === 'https://evil-attacker.com')) {
      findings.push({
        severity: 'critical',
        category: 'api-cors',
        title: `API CORS Credentials Misconfiguration: ${apiHost}`,
        description: `The API at ${apiUrl} allows credentials with a permissive CORS policy. This is a serious security risk.`,
        fix: 'Never use Access-Control-Allow-Credentials: true with wildcard or reflected origins.'
      });
    }

    // 2. Check for exposed health/debug endpoints
    const sensitiveApiPaths = ['/health', '/debug', '/status', '/info', '/metrics', '/swagger', '/docs', '/openapi.json'];

    for (const path of sensitiveApiPaths) {
      try {
        const endpointUrl = new URL(path, apiUrl).toString();
        const endpointResponse = await axios.get(endpointUrl, {
          ...axiosConfig,
          timeout: 5000,
          validateStatus: () => true
        });

        if (endpointResponse.status === 200) {
          const body = typeof endpointResponse.data === 'string'
            ? endpointResponse.data
            : JSON.stringify(endpointResponse.data);

          // Check if it reveals sensitive info
          if (body.includes('version') || body.includes('debug') ||
              body.includes('database') || body.includes('redis') ||
              body.includes('swagger') || body.includes('openapi')) {
            findings.push({
              severity: path.includes('debug') ? 'high' : 'medium',
              category: 'api-exposure',
              title: `API Endpoint Exposed: ${apiHost}${path}`,
              description: `The API has an exposed ${path} endpoint that may reveal sensitive information.`,
              fix: `Restrict access to ${path} or remove it in production.`
            });
          }

          // Check for secrets in response
          checkSecretsInResponse(body, endpointUrl, findings);
        }
      } catch (e) {}
    }

    // 3. Check for X-Powered-By and Server version disclosure
    if (headers['x-powered-by']) {
      findings.push({
        severity: 'low',
        category: 'api-disclosure',
        title: `API Technology Disclosed: ${apiHost}`,
        description: `The API reveals X-Powered-By: ${headers['x-powered-by']}`,
        fix: 'Remove the X-Powered-By header from API responses.'
      });
    }

    if (headers['server'] && /[0-9]+\.[0-9]+/.test(headers['server'])) {
      findings.push({
        severity: 'low',
        category: 'api-disclosure',
        title: `API Server Version Disclosed: ${apiHost}`,
        description: `The API reveals Server: ${headers['server']}`,
        fix: 'Remove or obscure the Server header to prevent version fingerprinting.'
      });
    }

  } catch (error) {
    // API not reachable, that's fine
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

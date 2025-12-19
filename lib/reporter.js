function generateReport(results, options = {}) {
  if (options.json) {
    return JSON.stringify(results, null, 2);
  }
  
  if (options.markdown) {
    return generateMarkdownReport(results);
  }
  
  return results;
}

function generateMarkdownReport(results) {
  const { url, findings, score, scanTime, timestamp } = results;
  
  let md = `# Security Scan Report

**Target:** ${url}  
**Score:** ${score}/100 ${getGrade(score)}  
**Scan Time:** ${scanTime}ms  
**Date:** ${timestamp}

---

## Summary

`;

  const bySeverity = {
    critical: findings.filter(f => f.severity === 'critical'),
    high: findings.filter(f => f.severity === 'high'),
    medium: findings.filter(f => f.severity === 'medium'),
    low: findings.filter(f => f.severity === 'low'),
    info: findings.filter(f => f.severity === 'info')
  };

  if (findings.length === 0) {
    md += `✅ **No security issues found!**\n\n`;
    md += `Your application passed all security checks.\n`;
    return md;
  }

  md += `| Severity | Count |\n|----------|-------|\n`;
  if (bySeverity.critical.length) md += `| 🔴 Critical | ${bySeverity.critical.length} |\n`;
  if (bySeverity.high.length) md += `| 🟠 High | ${bySeverity.high.length} |\n`;
  if (bySeverity.medium.length) md += `| 🟡 Medium | ${bySeverity.medium.length} |\n`;
  if (bySeverity.low.length) md += `| 🟢 Low | ${bySeverity.low.length} |\n`;
  if (bySeverity.info.length) md += `| ℹ️ Info | ${bySeverity.info.length} |\n`;

  md += `\n---\n\n## Findings\n\n`;

  // AI Instructions
  md += `> **AI Assistant Instructions:** Each finding below includes a severity level, description, and fix. `;
  md += `Apply fixes in order of severity (critical first). Code snippets are provided where applicable.\n\n`;

  // Group by category for better organization
  const byCategory = {};
  for (const finding of findings) {
    if (!byCategory[finding.category]) {
      byCategory[finding.category] = [];
    }
    byCategory[finding.category].push(finding);
  }

  const categoryOrder = ['secrets', 'exposure', 'headers', 'cors', 'cookies', 'api', 'config', 'disclosure'];
  const categoryTitles = {
    secrets: '🔐 Exposed Secrets',
    exposure: '📂 Exposed Files',
    headers: '🛡️ Security Headers',
    cors: '🌐 CORS Configuration',
    cookies: '🍪 Cookie Security',
    api: '🔌 API Security',
    config: '⚙️ Configuration Issues',
    disclosure: '📢 Information Disclosure'
  };

  for (const category of categoryOrder) {
    const categoryFindings = byCategory[category];
    if (!categoryFindings || categoryFindings.length === 0) continue;

    md += `### ${categoryTitles[category] || category}\n\n`;

    for (const finding of categoryFindings) {
      md += generateFindingMarkdown(finding);
    }
  }

  // Quick fix section
  md += `---\n\n## Quick Fixes\n\n`;
  md += `Here are the most impactful fixes to apply immediately:\n\n`;

  const criticalAndHigh = [...bySeverity.critical, ...bySeverity.high];
  if (criticalAndHigh.length > 0) {
    for (let i = 0; i < Math.min(5, criticalAndHigh.length); i++) {
      const finding = criticalAndHigh[i];
      md += `${i + 1}. **${finding.title}**: ${finding.fix}\n`;
    }
  } else {
    md += `No critical or high severity issues found.\n`;
  }

  // Framework-specific fixes
  md += `\n---\n\n## Framework-Specific Recommendations\n\n`;
  md += generateFrameworkRecommendations(findings);

  return md;
}

function generateFindingMarkdown(finding) {
  const severityBadge = {
    critical: '🔴 CRITICAL',
    high: '🟠 HIGH',
    medium: '🟡 MEDIUM',
    low: '🟢 LOW',
    info: 'ℹ️ INFO'
  };

  let md = `#### ${severityBadge[finding.severity]}: ${finding.title}\n\n`;
  md += `**Description:** ${finding.description}\n\n`;
  
  if (finding.url) {
    md += `**Location:** \`${finding.url}\`\n\n`;
  }
  
  if (finding.current) {
    md += `**Current Value:** \`${finding.current}\`\n\n`;
  }
  
  if (finding.evidence) {
    md += `**Evidence:** \`${finding.evidence}\`\n\n`;
  }
  
  md += `**Fix:** ${finding.fix}\n\n`;
  
  if (finding.code) {
    md += `**Implementation:**\n\n\`\`\`javascript\n${finding.code}\n\`\`\`\n\n`;
  }
  
  md += `---\n\n`;
  
  return md;
}

function generateFrameworkRecommendations(findings) {
  let md = '';
  
  // Check what categories of issues exist
  const hasHeaderIssues = findings.some(f => f.category === 'headers');
  const hasCookieIssues = findings.some(f => f.category === 'cookies');
  const hasExposureIssues = findings.some(f => f.category === 'exposure');
  
  if (hasHeaderIssues) {
    md += `### Next.js Security Headers\n\n`;
    md += `Add this to your \`next.config.js\`:\n\n`;
    md += `\`\`\`javascript
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
\`\`\`\n\n`;

    md += `### Express.js with Helmet\n\n`;
    md += `\`\`\`javascript
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
\`\`\`\n\n`;
  }
  
  if (hasCookieIssues) {
    md += `### Secure Cookie Configuration\n\n`;
    md += `\`\`\`javascript
// Express session
app.use(session({
  cookie: {
    secure: true,      // Only send over HTTPS
    httpOnly: true,    // Prevent XSS access
    sameSite: 'strict' // Prevent CSRF
  }
}));

// NextAuth.js
// In next.config.js or auth config
cookies: {
  sessionToken: {
    name: 'session-token',
    options: {
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      secure: process.env.NODE_ENV === 'production'
    }
  }
}
\`\`\`\n\n`;
  }
  
  if (hasExposureIssues) {
    md += `### Block Sensitive Files\n\n`;
    md += `**Nginx:**\n\`\`\`nginx
location ~ /\\. {
    deny all;
}
location ~ \\.(env|git|sql|log)$ {
    deny all;
}
\`\`\`\n\n`;
    
    md += `**Vercel (vercel.json):**\n\`\`\`json
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        { "key": "X-Content-Type-Options", "value": "nosniff" }
      ]
    }
  ],
  "rewrites": [
    { "source": "/.env", "destination": "/404" },
    { "source": "/.git/:path*", "destination": "/404" }
  ]
}
\`\`\`\n\n`;
  }
  
  if (md === '') {
    md = 'No framework-specific recommendations needed based on the findings.\n';
  }
  
  return md;
}

function getGrade(score) {
  if (score >= 90) return '(A+)';
  if (score >= 80) return '(A)';
  if (score >= 70) return '(B)';
  if (score >= 60) return '(C)';
  if (score >= 50) return '(D)';
  return '(F)';
}

module.exports = { generateReport };

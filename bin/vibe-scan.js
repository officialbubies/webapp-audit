#!/usr/bin/env node

const { program } = require('commander');
const chalk = require('chalk');
const ora = require('ora');
const { scanUrl } = require('../lib/scanner');
const { generateReport } = require('../lib/reporter');

program
  .name('webapp-audit')
  .description('Security audit tool for web applications')
  .version('1.0.0');

program
  .argument('<url>', 'URL to scan')
  .option('-o, --output <file>', 'Output markdown report to file')
  .option('-j, --json', 'Output as JSON')
  .option('-v, --verbose', 'Show detailed scan progress')
  .option('--no-color', 'Disable colored output')
  .option('--deep', 'Enable deep scan (slower, uses headless browser)')
  .option('--timeout <ms>', 'Request timeout in milliseconds', '30000')
  .action(async (url, options) => {
    console.log(chalk.bold.cyan('\n🛡️  WebApp Audit v1.0.0\n'));

    // Normalize URL
    if (!url.startsWith('http')) {
      url = 'https://' + url;
    }

    console.log(chalk.gray(`Target: ${url}\n`));

    // Verbose logger
    const verbose = (msg) => {
      if (options.verbose) {
        console.log(chalk.dim(`  → ${msg}`));
      }
    };

    const spinner = options.verbose ? null : ora('Scanning...').start();
    if (options.verbose) console.log(chalk.cyan('Starting scan...\n'));

    try {
      const results = await scanUrl(url, {
        deep: options.deep,
        timeout: parseInt(options.timeout),
        verbose: options.verbose ? verbose : null
      });

      if (spinner) spinner.stop();
      
      // Generate and display report
      const report = generateReport(results, { json: options.json });
      
      if (options.json) {
        console.log(JSON.stringify(results, null, 2));
      } else {
        displayResults(results);
      }
      
      // Save to file if requested
      if (options.output) {
        const fs = require('fs');
        const markdown = generateReport(results, { markdown: true });
        fs.writeFileSync(options.output, markdown);
        console.log(chalk.green(`\n✅ Report saved to ${options.output}`));
      }
      
      // Exit code based on findings
      const criticalCount = results.findings.filter(f => f.severity === 'critical').length;
      const highCount = results.findings.filter(f => f.severity === 'high').length;
      
      if (criticalCount > 0) process.exit(2);
      if (highCount > 0) process.exit(1);
      process.exit(0);
      
    } catch (error) {
      spinner.fail(chalk.red('Scan failed'));
      console.error(chalk.red(`\nError: ${error.message}`));
      process.exit(1);
    }
  });

function displayResults(results) {
  const { findings, score, url, context } = results;

  // Summary
  console.log(chalk.bold('\n📊 Security Score: ') + getScoreDisplay(score));
  console.log(chalk.gray(`   Scanned: ${url}`));
  console.log(chalk.gray(`   Time: ${results.scanTime}ms`));

  // Show detected technologies
  if (context && (context.framework || context.hosting)) {
    const tech = [];
    if (context.framework) tech.push(`Framework: ${context.framework}`);
    if (context.hosting) tech.push(`Hosting: ${context.hosting}`);
    console.log(chalk.cyan(`   Detected: ${tech.join(' | ')}`));
  }
  console.log('');
  
  if (findings.length === 0) {
    console.log(chalk.green('✅ No security issues found!\n'));
    return;
  }
  
  // Group by severity
  const critical = findings.filter(f => f.severity === 'critical');
  const high = findings.filter(f => f.severity === 'high');
  const medium = findings.filter(f => f.severity === 'medium');
  const low = findings.filter(f => f.severity === 'low');
  const info = findings.filter(f => f.severity === 'info');
  
  console.log(chalk.bold('📋 Findings Summary:'));
  if (critical.length) console.log(chalk.red(`   🔴 Critical: ${critical.length}`));
  if (high.length) console.log(chalk.yellow(`   🟠 High: ${high.length}`));
  if (medium.length) console.log(chalk.blue(`   🟡 Medium: ${medium.length}`));
  if (low.length) console.log(chalk.gray(`   🟢 Low: ${low.length}`));
  if (info.length) console.log(chalk.gray(`   ℹ️  Info: ${info.length}`));
  
  console.log(chalk.bold('\n─────────────────────────────────────────\n'));
  
  // Display each finding
  for (const finding of findings) {
    displayFinding(finding);
  }
  
  console.log(chalk.cyan('\n💡 Tip: Use --output report.md to generate an AI-friendly report\n'));
}

function displayFinding(finding) {
  const severityColors = {
    critical: chalk.bgRed.white.bold,
    high: chalk.bgYellow.black.bold,
    medium: chalk.bgBlue.white,
    low: chalk.bgGray.white,
    info: chalk.bgCyan.black
  };

  const colorFn = severityColors[finding.severity] || chalk.white;

  console.log(colorFn(` ${finding.severity.toUpperCase()} `) + ' ' + chalk.bold(finding.title));
  console.log(chalk.gray(`   Category: ${finding.category}`));
  console.log(`   ${finding.description}`);

  if (finding.fix) {
    console.log(chalk.green(`   Fix: ${finding.fix}`));
  }

  // Show context explanation if available
  if (finding.context) {
    console.log(chalk.yellow(`   ${finding.context}`));
  }

  if (finding.code) {
    console.log(chalk.gray('   ```'));
    console.log(chalk.yellow(`   ${finding.code.split('\n').join('\n   ')}`));
    console.log(chalk.gray('   ```'));
  }

  console.log('');
}

function getScoreDisplay(score) {
  if (score >= 90) return chalk.green.bold(`${score}/100 (A+)`);
  if (score >= 80) return chalk.green(`${score}/100 (A)`);
  if (score >= 70) return chalk.yellow(`${score}/100 (B)`);
  if (score >= 60) return chalk.yellow(`${score}/100 (C)`);
  if (score >= 50) return chalk.red(`${score}/100 (D)`);
  return chalk.bgRed.white.bold(` ${score}/100 (F) `);
}

program.parse();

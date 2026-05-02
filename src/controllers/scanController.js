const dns = require("node:dns/promises");
const tls = require("node:tls");
const Alert = require("../models/Alert");
const Report = require("../models/Report");
const Scan = require("../models/Scan");
const Website = require("../models/Website");
const { getStandards } = require("../config/securityStandards");
const { emitToUser } = require("../socket");

const REQUEST_TIMEOUT_MS = 10000;
const SENSITIVE_PATHS = [
  "/.git/",
  "/.env",
  "/admin/",
  "/backup/",
  "/config/",
  "/logs/",
  "/phpinfo.php",
  "/.htaccess",
  "/wp-admin/",
  "/api/docs",
  "/swagger.json",
  "/.DS_Store",
  "/database.sql"
];
const SQL_ERROR_PATTERNS = [
  /sql syntax/i,
  /mysql/i,
  /postgresql/i,
  /sqlstate/i,
  /sqlite/i,
  /odbc sql server driver/i,
  /unclosed quotation mark/i,
  /you have an error in your sql syntax/i
];
const LIBRARY_PATTERNS = {
  jquery: /jquery(?:\.min)?(?:[-.](\d+\.\d+(?:\.\d+)?))?/i,
  bootstrap: /bootstrap(?:\.bundle)?(?:\.min)?(?:[-.](\d+\.\d+(?:\.\d+)?))?/i,
  react: /react(?:\.production\.min|\.development)?(?:[-.](\d+\.\d+(?:\.\d+)?))?/i,
  angular: /angular(?:\.min)?(?:[-.](\d+\.\d+(?:\.\d+)?))?/i,
  vue: /vue(?:\.global|\.runtime|\.esm-browser)?(?:\.prod)?(?:\.min)?(?:[-.](\d+\.\d+(?:\.\d+)?))?/i,
  lodash: /lodash(?:\.min)?(?:[-.](\d+\.\d+(?:\.\d+)?))?/i,
  moment: /moment(?:\.min)?(?:[-.](\d+\.\d+(?:\.\d+)?))?/i
};
const LIBRARY_RULES = {
  jquery: {
    warnBelow: "3.7.1",
    cveBelow: "3.5.0",
    details: "Older jQuery releases include known XSS-related issues and are commonly beyond a two-year support window."
  },
  bootstrap: {
    warnBelow: "5.3.3",
    cveBelow: "4.3.1",
    details: "Older Bootstrap releases are frequently outdated and earlier branches include known client-side vulnerabilities."
  },
  react: {
    warnBelow: "18.3.1",
    cveBelow: null,
    details: "Older React releases may be outside the current maintenance window."
  },
  angular: {
    warnBelow: "17.3.0",
    cveBelow: null,
    details: "Angular versions behind current supported branches should be reviewed."
  },
  vue: {
    warnBelow: "3.4.0",
    cveBelow: null,
    details: "Older Vue releases may fall outside the current maintenance window."
  },
  lodash: {
    warnBelow: "4.17.21",
    cveBelow: "4.17.21",
    details: "Lodash versions below 4.17.21 have publicly known prototype pollution and command injection issues."
  },
  moment: {
    warnBelow: "2.30.0",
    cveBelow: "2.29.4",
    details: "Moment.js is legacy software and older versions should be upgraded or replaced."
  }
};
const XSS_SECURITY_HEADERS = ["content-security-policy", "x-xss-protection"];
const SECURITY_HEADER_RULES = [
  "content-security-policy",
  "strict-transport-security",
  "x-content-type-options",
  "x-frame-options",
  "referrer-policy",
  "permissions-policy"
];
const XSS_PROBES = [
  "inobyte-xss-probe",
  "inobyte-xss-marker-attr",
  "inobyte-xss-marker-svg"
];
const SCAN_SCHEDULES = {
  xss: "daily",
  sql_injection: "daily",
  missing_https: "daily",
  missing_security_headers: "daily",
  exposed_directories: "weekly",
  outdated_libraries: "weekly",
  weak_authentication: "weekly"
};
const THREAT_METADATA = {
  xss: {
    userTitle: "مشكلة قد تسمح بحقن محتوى ضار في الصفحة",
    technicalTitle: "Cross-Site Scripting (XSS)",
    definition: "The website reflects untrusted input in a way that could let an attacker run malicious JavaScript in a visitor's browser."
  },
  sql_injection: {
    userTitle: "ثغرة محتملة في قاعدة البيانات",
    technicalTitle: "SQL Injection Indicators",
    definition: "The website exposes database error patterns that may indicate unsafe SQL query handling or injection risk."
  },
  missing_https: {
    userTitle: "الموقع لا يستخدم اتصالا آمنا بشكل كاف",
    technicalTitle: "Missing HTTPS",
    definition: "The website is reachable without secure HTTPS transport, exposing user traffic to interception or tampering."
  },
  missing_security_headers: {
    userTitle: "إعدادات الحماية في المتصفح غير مكتملة",
    technicalTitle: "Missing Security Headers",
    definition: "The website is missing recommended browser security headers that help reduce common client-side attack impact."
  },
  exposed_directories: {
    userTitle: "ملفات أو مجلدات حساسة ظاهرة للعامة",
    technicalTitle: "Exposed Directories or Sensitive Files",
    definition: "The website exposes internal paths or sensitive files that should not be publicly reachable."
  },
  outdated_libraries: {
    userTitle: "مكتبات الموقع قديمة أو غير آمنة",
    technicalTitle: "Outdated or Vulnerable Libraries",
    definition: "The website uses client-side libraries that appear outdated or match vulnerable version heuristics."
  },
  weak_authentication: {
    userTitle: "حماية تسجيل الدخول ضعيفة",
    technicalTitle: "Weak Authentication Protection",
    definition: "Authentication endpoints appear to lack visible rate-limiting protections, increasing brute-force risk."
  }
};
const CHECK_DEFINITIONS = [
  {
    key: "xss",
    schedule: SCAN_SCHEDULES.xss,
    run: ({ baseUrl, homepage }) => checkXss(baseUrl, homepage)
  },
  {
    key: "sql_injection",
    schedule: SCAN_SCHEDULES.sql_injection,
    run: ({ homepage }) => checkSqlInjection(homepage)
  },
  {
    key: "missing_https",
    schedule: SCAN_SCHEDULES.missing_https,
    run: ({ homepage, target }) => checkMissingHttps(homepage, target)
  },
  {
    key: "missing_security_headers",
    schedule: SCAN_SCHEDULES.missing_security_headers,
    run: ({ homepage }) => checkMissingSecurityHeaders(homepage)
  },
  {
    key: "exposed_directories",
    schedule: SCAN_SCHEDULES.exposed_directories,
    run: ({ baseUrl }) => checkExposedDirectories(baseUrl)
  },
  {
    key: "outdated_libraries",
    schedule: SCAN_SCHEDULES.outdated_libraries,
    run: ({ baseUrl, homepage }) => checkOutdatedLibraries(baseUrl, homepage)
  },
  {
    key: "weak_authentication",
    schedule: SCAN_SCHEDULES.weak_authentication,
    run: ({ baseUrl }) => checkWeakAuthentication(baseUrl)
  }
];
const AUTH_PATHS = ["/login", "/signin", "/auth/login", "/users/login", "/api/login"];
const RATE_LIMIT_HEADER_NAMES = [
  "ratelimit-limit",
  "ratelimit-remaining",
  "x-ratelimit-limit",
  "x-ratelimit-remaining",
  "retry-after"
];

const normalizeDomainUrl = (domain, protocol = "https:") => {
  const value = String(domain || "").trim().toLowerCase();
  return new URL(`${protocol}//${value}`);
};

const fetchWithTimeout = async (url, options = {}) => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    return await fetch(url, {
      redirect: "manual",
      ...options,
      signal: controller.signal
    });
  } finally {
    clearTimeout(timeout);
  }
};

const safeFetchText = async (url, options = {}) => {
  try {
    const response = await fetchWithTimeout(url, options);
    const text = await response.text();

    return {
      ok: true,
      url,
      status: response.status,
      headers: response.headers,
      text
    };
  } catch (err) {
    return {
      ok: false,
      url,
      error: err.name === "AbortError" ? "Request timed out" : err.message
    };
  }
};

const resolveBaseTarget = async (domain) => {
  const httpsUrl = normalizeDomainUrl(domain, "https:");
  const httpUrl = normalizeDomainUrl(domain, "http:");
  const httpsHomepage = await safeFetchText(httpsUrl.toString(), { method: "GET" });

  if (httpsHomepage.ok) {
    return {
      baseUrl: httpsUrl,
      homepage: httpsHomepage,
      httpsUrl,
      httpUrl,
      httpsHomepage,
      httpHomepage: null
    };
  }

  const httpHomepage = await safeFetchText(httpUrl.toString(), { method: "GET" });

  if (httpHomepage.ok) {
    return {
      baseUrl: httpUrl,
      homepage: httpHomepage,
      httpsUrl,
      httpUrl,
      httpsHomepage,
      httpHomepage
    };
  }

  return {
    baseUrl: httpsUrl,
    homepage: null,
    httpsUrl,
    httpUrl,
    httpsHomepage,
    httpHomepage
  };
};

const compareVersions = (left, right) => {
  const leftParts = String(left || "0").split(".").map((value) => Number.parseInt(value, 10) || 0);
  const rightParts = String(right || "0").split(".").map((value) => Number.parseInt(value, 10) || 0);
  const max = Math.max(leftParts.length, rightParts.length);

  for (let index = 0; index < max; index += 1) {
    const a = leftParts[index] || 0;
    const b = rightParts[index] || 0;

    if (a > b) return 1;
    if (a < b) return -1;
  }

  return 0;
};

const severityRank = {
  NONE: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3
};

const maxSeverity = (values) => values.reduce((current, next) => (
  severityRank[next] > severityRank[current] ? next : current
), "NONE");

const buildOverallRisk = (items) => {
  const highCount = items.filter((item) => item.severity === "HIGH").length;
  const mediumCount = items.filter((item) => item.severity === "MEDIUM").length;
  const lowCount = items.filter((item) => item.severity === "LOW").length;

  if (highCount >= 2) return "CRITICAL";
  if (highCount === 1) return "HIGH";
  if (mediumCount >= 1) return "MEDIUM";
  if (lowCount >= 1) return "LOW";
  return "SAFE";
};

const buildScanId = () => `scan-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

const withSchedule = (key, result) => ({
  ...result,
  schedule: SCAN_SCHEDULES[key]
});
const isThreatDetected = (item) => item?.status === "VULNERABLE";

const buildSummary = (vulnerabilities) => {
  const entries = Object.entries(vulnerabilities);

  return {
    total_checks: entries.length,
    vulnerable: entries.filter(([, item]) => item.status === "VULNERABLE").length,
    safe: entries.filter(([, item]) => item.status === "SAFE").length,
    unknown: entries.filter(([, item]) => item.status === "UNKNOWN").length,
    threats_found: entries.filter(([, item]) => isThreatDetected(item)).map(([key]) => key),
    threats_safe: entries
      .filter(([, item]) => item.status === "SAFE")
      .map(([key]) => key)
  };
};

const buildFrontendThreatReport = (targetUrl, vulnerabilities) => {
  const detectedThreats = Object.entries(vulnerabilities)
    .filter(([, item]) => isThreatDetected(item))
    .map(([key, item]) => ({
      key,
      user_title: THREAT_METADATA[key]?.userTitle || key,
      technical_title: THREAT_METADATA[key]?.technicalTitle || key,
      title: THREAT_METADATA[key]?.userTitle || key,
      definition: THREAT_METADATA[key]?.definition || item.details,
      status: item.status,
      severity: item.severity,
      schedule: item.schedule,
      details: item.details,
      evidence: item.evidence || item.found_paths || item.libraries_found || null
    }));

  return {
    title: "Inobyte Security Scan Report",
    description: "Threat summary generated from the latest website scan.",
    target_url: targetUrl,
    threats_detected_count: detectedThreats.length,
    threats_detected: detectedThreats
  };
};

const buildStoredReportPayload = (scanReport, scanType) => ({
  scanId: scanReport.scan_id,
  scanType,
  targetUrl: scanReport.target_url,
  title: scanReport.report.title,
  description: scanReport.report.description,
  summary: scanReport.summary,
  threatsDetectedCount: scanReport.report.threats_detected_count,
  threatsDetected: scanReport.report.threats_detected,
  overallRisk: scanReport.overall_risk,
  generatedAt: new Date()
});

const createStoredReport = async ({ userId, websiteId, scanType, scanReport }) => Report.create({
  userId,
  websiteId,
  ...buildStoredReportPayload(scanReport, scanType)
});

const checkDns = async (hostname) => {
  try {
    const addresses = await dns.lookup(hostname, { all: true });
    return {
      resolves: addresses.length > 0,
      addresses
    };
  } catch (err) {
    return {
      resolves: false,
      error: err.message
    };
  }
};

const checkTlsCertificate = (hostname, port = 443) => new Promise((resolve) => {
  const socket = tls.connect({
    host: hostname,
    port,
    servername: hostname,
    rejectUnauthorized: false,
    timeout: REQUEST_TIMEOUT_MS
  });

  socket.once("secureConnect", () => {
    const certificate = socket.getPeerCertificate();
    const validTo = certificate.valid_to ? new Date(certificate.valid_to) : null;

    resolve({
      available: true,
      authorized: socket.authorized,
      authorizationError: socket.authorizationError || null,
      validTo,
      daysUntilExpiry: validTo
        ? Math.ceil((validTo.getTime() - Date.now()) / (24 * 60 * 60 * 1000))
        : null
    });

    socket.end();
  });

  socket.once("timeout", () => {
    resolve({
      available: false,
      error: "TLS connection timed out"
    });
    socket.destroy();
  });

  socket.once("error", (err) => {
    resolve({
      available: false,
      error: err.message
    });
  });
});

const buildProbeUrl = (baseUrl, paramName, value) => {
  const url = new URL(baseUrl.toString());
  url.searchParams.set(paramName, value);
  return url;
};

const checkXss = async (baseUrl, homepage) => {
  if (!homepage?.ok) {
    return {
      status: "UNKNOWN",
      severity: "NONE",
      details: "Homepage could not be fetched, so passive XSS checks were inconclusive.",
      evidence: homepage?.error || "No response from target.",
      alert: false
    };
  }

  const reflections = [];

  for (const probe of XSS_PROBES) {
    const probeUrl = buildProbeUrl(baseUrl, "xss_probe", probe);
    const response = await safeFetchText(probeUrl.toString(), { method: "GET" });

    if (response.ok && response.text.includes(probe)) {
      reflections.push({
        probe,
        url: probeUrl.toString()
      });
    }
  }

  const csp = homepage.headers.get("content-security-policy");
  const xssProtection = homepage.headers.get("x-xss-protection");

  if (reflections.length) {
    return {
      status: "VULNERABLE",
      severity: csp ? "MEDIUM" : "HIGH",
      details: "User-controlled probe values were reflected in the HTML response without sanitization.",
      evidence: reflections.map((item) => `${item.probe} reflected at ${item.url}`).join("; "),
      alert: true
    };
  }

  const missingHeaders = XSS_SECURITY_HEADERS.filter((header) => !homepage.headers.get(header));

  return {
    status: "SAFE",
    severity: missingHeaders.length ? "LOW" : "NONE",
    details: missingHeaders.length
      ? `No probe reflection was found, but hardening headers were missing: ${missingHeaders.join(", ")}.`
      : "No probe reflection was found and XSS hardening headers were present.",
    evidence: `Content-Security-Policy=${csp || "missing"}; X-XSS-Protection=${xssProtection || "missing"}`,
    alert: false
  };
};

const checkMissingHttps = async (homepage, target) => {
  if (target?.httpsHomepage?.ok) {
    return {
      status: "SAFE",
      severity: "NONE",
      details: "HTTPS was available for the target.",
      evidence: `HTTPS response status: ${target.httpsHomepage.status}`,
      alert: false
    };
  }

  if (target?.httpHomepage?.ok) {
    return {
      status: "VULNERABLE",
      severity: "HIGH",
      details: "The target responded over HTTP but HTTPS was not available.",
      evidence: `HTTP reachable at ${target.httpUrl.toString()}; HTTPS error: ${target.httpsHomepage?.error || "no successful HTTPS response"}`,
      alert: true
    };
  }

  return {
    status: "UNKNOWN",
    severity: "NONE",
    details: "Transport security could not be assessed because the target did not respond over HTTP or HTTPS.",
    evidence: homepage?.error || target?.httpsHomepage?.error || "No response from target.",
    alert: false
  };
};

const checkMissingSecurityHeaders = async (homepage) => {
  if (!homepage?.ok) {
    return {
      status: "UNKNOWN",
      severity: "NONE",
      details: "Homepage could not be fetched, so security header validation was inconclusive.",
      evidence: homepage?.error || "No response from target.",
      alert: false
    };
  }

  const missingHeaders = SECURITY_HEADER_RULES.filter((header) => !homepage.headers.get(header));

  if (!missingHeaders.length) {
    return {
      status: "SAFE",
      severity: "NONE",
      details: "Common browser security headers were present on the homepage response.",
      evidence: SECURITY_HEADER_RULES.map((header) => `${header}=present`).join("; "),
      alert: false
    };
  }

  return {
    status: "VULNERABLE",
    severity: missingHeaders.length >= 4 ? "HIGH" : "MEDIUM",
    details: "One or more recommended browser security headers were missing.",
    evidence: `Missing headers: ${missingHeaders.join(", ")}`,
    alert: true
  };
};

const checkSqlInjection = async (homepage) => {
  if (!homepage?.ok) {
    return {
      status: "UNKNOWN",
      severity: "NONE",
      details: "Target could not be fetched, so passive SQL error review was inconclusive.",
      evidence: homepage?.error || "No response from target.",
      alert: false
    };
  }

  const matches = SQL_ERROR_PATTERNS.filter((pattern) => pattern.test(homepage.text));

  if (matches.length) {
    return {
      status: "VULNERABLE",
      severity: "MEDIUM",
      details: "The baseline response exposed database error signatures.",
      evidence: `Matched SQL error patterns: ${matches.map((pattern) => pattern.toString()).join(", ")}`,
      alert: true
    };
  }

  return {
    status: "UNKNOWN",
    severity: "NONE",
    details: "Active SQL injection payload testing is disabled in safe scan mode; no SQL error leakage was observed in the baseline response.",
    evidence: "Baseline response did not match common MySQL, PostgreSQL, MSSQL, or SQLite error patterns.",
    alert: false
  };
};

const buildPathSeverity = (path, status) => {
  if (status === 403) return "LOW";
  if (["/.git/", "/.env", "/database.sql", "/phpinfo.php", "/.DS_Store"].includes(path)) return "HIGH";
  return "MEDIUM";
};

const checkExposedDirectories = async (baseUrl) => {
  const settled = await Promise.all(SENSITIVE_PATHS.map(async (path) => {
    const targetUrl = new URL(path, baseUrl).toString();
    const result = await safeFetchText(targetUrl, { method: "GET" });

    if (!result.ok || (result.status !== 200 && result.status !== 403)) {
      return null;
    }

    const directoryListing = /<title>index of/i.test(result.text) || /directory listing/i.test(result.text);

    return {
      path,
      status: result.status,
      directoryListing,
      severity: directoryListing ? "HIGH" : buildPathSeverity(path, result.status)
    };
  }));
  const foundPaths = settled.filter(Boolean);

  const highestSeverity = maxSeverity(foundPaths.map((item) => item.severity));

  return {
    status: foundPaths.length ? "VULNERABLE" : "SAFE",
    severity: highestSeverity,
    found_paths: foundPaths.map(({ path, status, directoryListing }) => ({
      path,
      status,
      directoryListing
    })),
    details: foundPaths.length
      ? "Sensitive paths were reachable or disclosed access controls on the target."
      : "No common sensitive path returned 200 or 403 during this scan.",
    alert: foundPaths.length > 0
  };
};

const extractScriptSources = (html) => {
  const scripts = [];
  const regex = /<script\b[^>]*src=["']([^"']+)["'][^>]*>/gi;
  let match = regex.exec(html);

  while (match) {
    scripts.push(match[1]);
    match = regex.exec(html);
  }

  return scripts;
};

const toAbsoluteSameOriginUrl = (baseUrl, source) => {
  try {
    const parsed = new URL(source, baseUrl);

    if (parsed.origin !== baseUrl.origin) {
      return null;
    }

    return parsed;
  } catch {
    return null;
  }
};

const detectLibrariesInText = (text, sourceLabel) => {
  const found = [];

  for (const [name, pattern] of Object.entries(LIBRARY_PATTERNS)) {
    const match = text.match(pattern);

    if (match) {
      found.push({
        name,
        version: match[1] || null,
        source: sourceLabel
      });
    }
  }

  return found;
};

const dedupeLibraries = (libraries) => {
  const unique = new Map();

  for (const library of libraries) {
    const key = `${library.name}:${library.version || "unknown"}:${library.source}`;

    if (!unique.has(key)) {
      unique.set(key, library);
    }
  }

  return [...unique.values()];
};

const evaluateLibrary = (library) => {
  const rule = LIBRARY_RULES[library.name];

  if (!rule || !library.version) {
    return {
      ...library,
      severity: "LOW",
      reason: "Library detected but version could not be fully evaluated."
    };
  }

  if (rule.cveBelow && compareVersions(library.version, rule.cveBelow) < 0) {
    return {
      ...library,
      severity: "HIGH",
      reason: rule.details
    };
  }

  if (rule.warnBelow && compareVersions(library.version, rule.warnBelow) < 0) {
    return {
      ...library,
      severity: "MEDIUM",
      reason: rule.details
    };
  }

  return {
    ...library,
    severity: "NONE",
    reason: "Detected version does not match the local outdated/vulnerable heuristic."
  };
};

const checkOutdatedLibraries = async (baseUrl, homepage) => {
  if (!homepage?.ok) {
    return {
      status: "UNKNOWN",
      severity: "NONE",
      libraries_found: [],
      details: "Homepage could not be fetched, so script library detection was inconclusive.",
      alert: false
    };
  }

  const scripts = extractScriptSources(homepage.text);
  const detected = [
    ...detectLibrariesInText(homepage.text, baseUrl.toString())
  ];

  for (const script of scripts) {
    detected.push(...detectLibrariesInText(script, script));

    const absolute = toAbsoluteSameOriginUrl(baseUrl, script);

    if (!absolute) {
      continue;
    }

    const asset = await safeFetchText(absolute.toString(), { method: "GET" });

    if (asset.ok) {
      detected.push(...detectLibrariesInText(asset.text.slice(0, 4096), absolute.toString()));
    }
  }

  const evaluated = dedupeLibraries(detected).map(evaluateLibrary);
  const flagged = evaluated.filter((item) => item.severity === "MEDIUM" || item.severity === "HIGH");
  const highestSeverity = maxSeverity(flagged.map((item) => item.severity));

  return {
    status: flagged.length ? "VULNERABLE" : evaluated.length ? "SAFE" : "UNKNOWN",
    severity: flagged.length ? highestSeverity : evaluated.length ? "NONE" : "NONE",
    libraries_found: evaluated.map(({ name, version, source, severity, reason }) => ({
      name,
      version,
      source,
      severity,
      reason
    })),
    details: flagged.length
      ? "One or more client-side libraries matched outdated or vulnerable local heuristics."
      : evaluated.length
        ? "Libraries were detected and none matched the current local outdated/vulnerable heuristics."
        : "No recognizable JavaScript libraries were detected on same-origin assets.",
    alert: flagged.length > 0
  };
};

const checkWeakAuthentication = async (baseUrl) => {
  const findings = [];

  for (const path of AUTH_PATHS) {
    const url = new URL(path, baseUrl).toString();
    const response = await safeFetchText(url, { method: "GET" });

    if (!response.ok || ![200, 401, 403].includes(response.status)) {
      continue;
    }

    const rateLimitHeaders = RATE_LIMIT_HEADER_NAMES.filter((header) => response.headers.get(header));

    findings.push({
      path,
      status: response.status,
      rateLimitHeaders
    });
  }

  if (!findings.length) {
    return {
      status: "UNKNOWN",
      severity: "NONE",
      details: "No recognizable authentication endpoint was discovered for passive rate-limit inspection.",
      evidence: AUTH_PATHS.join(", "),
      alert: false
    };
  }

  const protectedEndpoints = findings.filter((item) => item.rateLimitHeaders.length > 0);

  if (protectedEndpoints.length) {
    return {
      status: "SAFE",
      severity: "LOW",
      details: "Authentication endpoint responses exposed rate-limiting indicators.",
      evidence: protectedEndpoints.map((item) => `${item.path}: ${item.rateLimitHeaders.join(", ")}`).join("; "),
      alert: false
    };
  }

  return {
    status: "VULNERABLE",
    severity: "MEDIUM",
    details: "Authentication endpoints were reachable but did not expose common rate-limiting indicators.",
    evidence: findings.map((item) => `${item.path} returned ${item.status}`).join("; "),
    alert: true
  };
};

const buildAlertRecords = (report, websiteId, userId) => {
  const records = [];
  const vulnerabilityEntries = Object.entries(report.vulnerabilities);

  for (const [key, item] of vulnerabilityEntries) {
    if (!isThreatDetected(item)) {
      continue;
    }

    records.push({
      userId,
      websiteId,
      message: `${key.replace(/_/g, " ")} detected on ${report.target_url}`,
      severity: item.severity.toLowerCase(),
      standards: {
        category: key,
        scanId: report.scan_id,
        details: item.details,
        evidence: item.evidence || item.found_paths || item.libraries_found || null
      }
    });
  }

  return records;
};

const summarizeAlerts = (report, previousReport = null) => {
  const active = Object.entries(report.vulnerabilities)
    .filter(([, value]) => isThreatDetected(value))
    .map(([key, value]) => `${key}:${value.severity}`);

  if (!active.length) {
    return "";
  }

  if (!previousReport?.vulnerabilities) {
    return `Security scan found ${active.join(", ")} on ${report.target_url}`;
  }

  const previousActive = Object.entries(previousReport.vulnerabilities)
    .filter(([, value]) => isThreatDetected(value))
    .map(([key, value]) => `${key}:${value.severity}`);

  const changed = active.join("|") !== previousActive.join("|");

  return changed
    ? `Security scan found ${active.join(", ")} on ${report.target_url}; findings changed since the previous scan`
    : `Security scan found ${active.join(", ")} on ${report.target_url}; findings match the previous scan`;
};

const setAllStatusesUnknown = (vulnerabilities) => {
  for (const item of Object.values(vulnerabilities)) {
    item.status = "UNKNOWN";
  }
};

const runScanChecks = async (domain, selectedKeys = CHECK_DEFINITIONS.map((item) => item.key)) => {
  const [{ resolves }, target] = await Promise.all([
    checkDns(domain),
    resolveBaseTarget(domain)
  ]);

  const homepage = target.homepage;
  const baseUrl = target.baseUrl;
  if (baseUrl.protocol === "https:") {
    await checkTlsCertificate(baseUrl.hostname, Number(baseUrl.port) || 443);
  }

  const selectedDefinitions = CHECK_DEFINITIONS.filter((item) => selectedKeys.includes(item.key));
  const results = await Promise.all(selectedDefinitions.map(async (definition) => ([
    definition.key,
    withSchedule(definition.key, await definition.run({ baseUrl, homepage, target }))
  ])));
  const vulnerabilities = Object.fromEntries(results);

  if (homepage?.ok === false && !resolves) {
    setAllStatusesUnknown(vulnerabilities);
  }

  const scanId = buildScanId();
  const vulnerabilityItems = Object.values(vulnerabilities);
  const overallRisk = buildOverallRisk(vulnerabilityItems);

  return {
    scan_date: new Date().toISOString().slice(0, 10),
    target_url: baseUrl.toString(),
    scan_id: scanId,
    vulnerabilities,
    summary: buildSummary(vulnerabilities),
    report: buildFrontendThreatReport(baseUrl.toString(), vulnerabilities),
    overall_risk: overallRisk,
    send_alert: vulnerabilityItems.some((item) => isThreatDetected(item)),
    alert_message: ""
  };
};

const scanTarget = async (domain) => runScanChecks(domain);

exports.scanWebsite = async (req, res) => {
  try {
    const { websiteId, previousScanId } = req.body;

    if (!websiteId) {
      return res.status(400).json({ msg: "websiteId is required" });
    }

    const website = await Website.findOne({
      _id: websiteId,
      userId: req.user.id
    }).select("_id domain verified");

    if (!website) {
      return res.status(404).json({ msg: "Website not found" });
    }

    if (!website.verified) {
      return res.status(400).json({ msg: "Website must be verified before scanning" });
    }

    const previousScan = previousScanId
      ? await Scan.findOne({
          websiteId: website._id,
          userId: req.user.id,
          "results.scan_id": previousScanId
        }).select("results")
      : await Scan.findOne({
          websiteId: website._id,
          userId: req.user.id
        }).sort({ createdAt: -1 }).select("results");

    const report = await scanTarget(website.domain);
    report.alert_message = summarizeAlerts(report, previousScan?.results || null);

    await Scan.create({
      userId: req.user.id,
      websiteId: website._id,
      url: report.target_url,
      status: "completed",
      scanType: "manual",
      results: report
    });

    const storedReport = await createStoredReport({
      userId: req.user.id,
      websiteId: website._id,
      scanType: "manual",
      scanReport: report
    });

    if (report.send_alert) {
      const alertRecords = buildAlertRecords(report, website._id, req.user.id);
      const alerts = await Alert.insertMany(alertRecords);

      for (const alert of alerts) {
        emitToUser(req.user.id, "new_alert", {
          id: alert._id,
          websiteId: alert.websiteId,
          message: alert.message,
          severity: alert.severity,
          timestamp: alert.createdAt
        });
      }
    }

    res.json({
      ...report,
      report: {
        id: storedReport._id,
        scan_id: storedReport.scanId,
        scan_type: storedReport.scanType,
        title: storedReport.title,
        description: storedReport.description,
        target_url: storedReport.targetUrl,
        summary: storedReport.summary,
        threats_detected_count: storedReport.threatsDetectedCount,
        threats_detected: storedReport.threatsDetected,
        overall_risk: storedReport.overallRisk,
        generated_at: storedReport.generatedAt
      }
    });
  } catch (err) {
    console.error(err);

    if (err.name === "AbortError") {
      return res.status(504).json({ msg: "Scan request timed out" });
    }

    res.status(500).json({ msg: "Server error" });
  }
};

exports.SCAN_SCHEDULES = SCAN_SCHEDULES;
exports.checkExposedDirectories = checkExposedDirectories;
exports.checkMissingHttps = checkMissingHttps;
exports.checkMissingSecurityHeaders = checkMissingSecurityHeaders;
exports.checkOutdatedLibraries = checkOutdatedLibraries;
exports.checkSqlInjection = checkSqlInjection;
exports.checkWeakAuthentication = checkWeakAuthentication;
exports.checkXss = checkXss;
exports.buildAlertRecords = buildAlertRecords;
exports.createStoredReport = createStoredReport;
exports.runScanChecks = runScanChecks;
exports.summarizeAlerts = summarizeAlerts;
exports.scanTarget = scanTarget;
exports.getStandards = () => ({
  xss: getStandards("SECURITY_HEADERS"),
  sql_injection: getStandards("SECURITY_MONITORING"),
  missing_https: getStandards("HTTPS_REQUIRED"),
  missing_security_headers: getStandards("SECURITY_HEADERS"),
  exposed_directories: getStandards("HTTP_AVAILABILITY"),
  outdated_libraries: getStandards("SECURITY_MONITORING"),
  weak_authentication: getStandards("SECURITY_MONITORING")
});

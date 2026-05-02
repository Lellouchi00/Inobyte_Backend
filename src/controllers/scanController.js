const dns = require("node:dns/promises");
const tls = require("node:tls");
const Scan = require("../models/Scan");
const Alert = require("../models/Alert");
const { buildStandardsSummary, getStandards } = require("../config/securityStandards");
const { emitToUser } = require("../socket");

const REQUEST_TIMEOUT_MS = 10000;
const SECURITY_HEADERS = {
  "strict-transport-security": "HTTP Strict Transport Security",
  "content-security-policy": "Content Security Policy",
  "x-frame-options": "Clickjacking protection",
  "x-content-type-options": "MIME sniffing protection",
  "referrer-policy": "Referrer Policy",
  "permissions-policy": "Permissions Policy"
};

const normalizeUrl = (value) => {
  const raw = value.trim();
  const withProtocol = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  const parsed = new URL(withProtocol);

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Only HTTP and HTTPS URLs are supported");
  }

  parsed.hash = "";
  return parsed;
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

const safeFetch = async (url, options = {}) => {
  try {
    const response = await fetchWithTimeout(url, options);

    return {
      ok: true,
      response
    };
  } catch (err) {
    return {
      ok: false,
      error: err.name === "AbortError" ? "Request timed out" : err.message
    };
  }
};

const checkDns = async (hostname) => {
  try {
    const [addresses, cname] = await Promise.all([
      dns.lookup(hostname, { all: true }),
      dns.resolveCname(hostname).catch(() => [])
    ]);

    return {
      resolves: addresses.length > 0,
      addresses: addresses.map((address) => ({
        address: address.address,
        family: address.family
      })),
      cname,
      standards: getStandards("DNS_RESOLUTION")
    };
  } catch (err) {
    return {
      resolves: false,
      error: err.message,
      standards: getStandards("DNS_RESOLUTION")
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
    const validFrom = certificate.valid_from ? new Date(certificate.valid_from) : null;

    resolve({
      available: true,
      authorized: socket.authorized,
      authorizationError: socket.authorizationError || null,
      issuer: certificate.issuer?.O || certificate.issuer?.CN || null,
      subject: certificate.subject?.CN || null,
      validFrom,
      validTo,
      daysUntilExpiry: validTo
        ? Math.ceil((validTo.getTime() - Date.now()) / (24 * 60 * 60 * 1000))
        : null,
      standards: getStandards("TLS_CERTIFICATE")
    });

    socket.end();
  });

  socket.once("timeout", () => {
    resolve({
      available: false,
      error: "TLS connection timed out",
      standards: getStandards("TLS_CERTIFICATE")
    });
    socket.destroy();
  });

  socket.once("error", (err) => {
    resolve({
      available: false,
      error: err.message,
      standards: getStandards("TLS_CERTIFICATE")
    });
  });
});

const collectHeaders = (headers) => {
  const present = {};
  const missing = [];

  for (const [header, label] of Object.entries(SECURITY_HEADERS)) {
    const value = headers.get(header);

    if (value) {
      present[header] = value;
    } else {
      missing.push({
        header,
        label,
        standards: getStandards("SECURITY_HEADERS")
      });
    }
  }

  return {
    present,
    missing,
    standards: getStandards("SECURITY_HEADERS")
  };
};

const checkHttpsRedirect = async (url) => {
  if (url.protocol !== "https:") {
    return {
      checked: false,
      redirectsToHttps: false,
      standards: getStandards("HTTPS_REDIRECT")
    };
  }

  const httpUrl = new URL(url.toString());
  httpUrl.protocol = "http:";

  const result = await safeFetch(httpUrl.toString(), { method: "GET" });

  if (!result.ok) {
    return {
      checked: true,
      redirectsToHttps: false,
      error: result.error,
      standards: getStandards("HTTPS_REDIRECT")
    };
  }

  const location = result.response.headers.get("location");

  return {
    checked: true,
    statusCode: result.response.status,
    location,
    redirectsToHttps: Boolean(location && location.startsWith("https://")),
    standards: getStandards("HTTPS_REDIRECT")
  };
};

const calculateScore = (checks) => {
  let score = 100;

  if (!checks.https.enabled) score -= 35;
  if (checks.https.enabled && !checks.tls.available) score -= 25;
  if (checks.tls.available && checks.tls.authorized === false) score -= 20;
  if (checks.tls.daysUntilExpiry !== null && checks.tls.daysUntilExpiry <= 14) score -= 15;
  if (checks.redirect.checked && !checks.redirect.redirectsToHttps) score -= 10;

  score -= checks.headers.missing.length * 7;

  return Math.max(0, Math.min(100, score));
};

const getRiskLevel = (score) => {
  if (score >= 80) return "low";
  if (score >= 60) return "medium";
  return "high";
};

const buildAlerts = (results) => {
  const alerts = [];

  if (!results.checks.https.enabled) {
    alerts.push({
      message: "Website is not using HTTPS",
      severity: "high",
      standards: getStandards("HTTPS_REQUIRED")
    });
  }

  if (results.checks.dns.resolves === false) {
    alerts.push({
      message: "Domain does not resolve",
      severity: "high",
      standards: getStandards("DNS_RESOLUTION")
    });
  }

  if (results.checks.http.reachable === false) {
    alerts.push({
      message: "Website did not respond to HTTP request",
      severity: "high",
      standards: getStandards("HTTP_AVAILABILITY")
    });
  }

  if (results.checks.tls.available && results.checks.tls.authorized === false) {
    alerts.push({
      message: "TLS certificate is not trusted",
      severity: "high",
      standards: getStandards("TLS_CERTIFICATE")
    });
  }

  if (results.checks.tls.daysUntilExpiry !== null && results.checks.tls.daysUntilExpiry <= 14) {
    alerts.push({
      message: "TLS certificate expires soon",
      severity: "medium",
      standards: getStandards("TLS_CERTIFICATE")
    });
  }

  for (const missing of results.checks.headers.missing) {
    alerts.push({
      message: `${missing.label} header is missing`,
      severity: missing.header === "content-security-policy" ? "medium" : "low",
      standards: getStandards("SECURITY_HEADERS")
    });
  }

  return alerts;
};

const scanTarget = async (targetUrl) => {
  const url = normalizeUrl(targetUrl);
  const dnsResult = await checkDns(url.hostname);
  const httpResult = await safeFetch(url.toString(), { method: "GET" });
  const headers = httpResult.ok
    ? collectHeaders(httpResult.response.headers)
    : {
        present: {},
        missing: Object.entries(SECURITY_HEADERS).map(([header, label]) => ({
          header,
          label,
          standards: getStandards("SECURITY_HEADERS")
        })),
        standards: getStandards("SECURITY_HEADERS")
      };
  const redirect = await checkHttpsRedirect(url);
  const tlsResult = url.protocol === "https:"
    ? await checkTlsCertificate(url.hostname, Number(url.port) || 443)
    : {
        available: false,
        error: "HTTPS is not enabled",
        standards: getStandards("TLS_CERTIFICATE")
      };

  const checks = {
    dns: dnsResult,
    https: {
      enabled: url.protocol === "https:",
      standards: getStandards("HTTPS_REQUIRED")
    },
    http: {
      reachable: httpResult.ok,
      statusCode: httpResult.ok ? httpResult.response.status : null,
      finalUrl: url.toString(),
      server: httpResult.ok ? httpResult.response.headers.get("server") : null,
      poweredBy: httpResult.ok ? httpResult.response.headers.get("x-powered-by") : null,
      error: httpResult.ok ? null : httpResult.error,
      standards: getStandards("HTTP_AVAILABILITY")
    },
    redirect,
    tls: tlsResult,
    headers
  };
  const score = calculateScore(checks);

  return {
    target: {
      input: targetUrl,
      normalizedUrl: url.toString(),
      hostname: url.hostname
    },
    score,
    riskLevel: getRiskLevel(score),
    standards: buildStandardsSummary([
      "DNS_RESOLUTION",
      "HTTPS_REQUIRED",
      "TLS_CERTIFICATE",
      "HTTPS_REDIRECT",
      "SECURITY_HEADERS",
      "HTTP_AVAILABILITY"
    ]),
    checks,
    alerts: buildAlerts({ checks })
  };
};

exports.scanWebsite = async (req, res) => {
  try {
    const { url } = req.body;

    if (!url || typeof url !== "string") {
      return res.status(400).json({ msg: "URL is required" });
    }

    const results = await scanTarget(url);

    const scan = await Scan.create({
      userId: req.user.id,
      url: results.target.normalizedUrl,
      status: "completed",
      results
    });

    if (results.alerts.length) {
      const alerts = await Alert.insertMany(results.alerts.map((alert) => ({
        userId: req.user.id,
        message: alert.message,
        severity: alert.severity,
        standards: alert.standards
      })));

      for (const alert of alerts) {
        emitToUser(req.user.id, "new_alert", {
          id: alert._id,
          message: alert.message,
          severity: alert.severity,
          timestamp: alert.createdAt
        });
      }
    }

    res.json(scan);
  } catch (err) {
    console.error(err);

    if (err.name === "AbortError") {
      return res.status(504).json({ msg: "Scan request timed out" });
    }

    if (err.message.includes("Invalid URL") || err.message.includes("Only HTTP")) {
      return res.status(400).json({ msg: err.message });
    }

    res.status(500).json({ msg: "Server error" });
  }
};

exports.scanTarget = scanTarget;

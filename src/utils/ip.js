const net = require("node:net");

const IPV4_PRIVATE_RANGES = [
  /^10\./,
  /^127\./,
  /^169\.254\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[0-1])\./,
  /^0\./
];

const normalizeIp = (value = "") => value
  .replace(/^::ffff:/, "")
  .replace(/^\[|\]$/g, "")
  .trim();

const isPrivateIp = (value) => {
  const ip = normalizeIp(value);

  if (!ip) return true;
  if (ip === "::1" || ip === "localhost") return true;

  if (net.isIPv4(ip)) {
    return IPV4_PRIVATE_RANGES.some((range) => range.test(ip));
  }

  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    return lower.startsWith("fc") || lower.startsWith("fd") || lower.startsWith("fe80") || lower === "::";
  }

  return false;
};

const getClientIp = (req) => {
  const forwarded = String(req.headers["x-forwarded-for"] || "")
    .split(",")
    .map(normalizeIp)
    .filter(Boolean);
  const candidates = [
    ...forwarded,
    normalizeIp(req.ip),
    normalizeIp(req.socket?.remoteAddress)
  ].filter(Boolean);

  return candidates.find((ip) => !isPrivateIp(ip)) || null;
};

module.exports = {
  getClientIp,
  isPrivateIp,
  normalizeIp
};

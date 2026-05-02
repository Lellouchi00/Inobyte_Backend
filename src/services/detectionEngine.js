const Alert = require("../models/Alert");
const Event = require("../models/Event");
const { getStandards } = require("../config/securityStandards");
const { getCountryFromLocation } = require("./locationService");

const TWO_HOURS_MS = 2 * 60 * 60 * 1000;
const ONE_MINUTE_MS = 60 * 1000;
const BRUTE_FORCE_THRESHOLD = 50;
const RATE_LIMIT_THRESHOLD = 1000;
const RISKY_SOFTWARE_KEYWORDS = ["cracked", "keygen", "patcher", "activator", "torrent"];
const EXECUTABLE_EXTENSIONS = ["exe", "dll", "scr", "bat", "cmd", "ps1", "msi", "com"];
const DOCUMENT_EXTENSIONS = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt"];

const lower = (value) => String(value || "").trim().toLowerCase();
const hasAnyKeyword = (value, keywords) => keywords.some((keyword) => lower(value).includes(keyword));
const getActorId = (event) => (
  event.data?.accountId ||
  event.data?.userId ||
  event.data?.actorId ||
  event.data?.sessionId ||
  event.ip ||
  event.apiKey
);
const buildActorScope = (event, actorId) => {
  const conditions = [{ apiKey: event.apiKey }];

  if (event.ip) {
    conditions.push({ ip: event.ip });
  }

  if (actorId) {
    conditions.push(
      { "data.accountId": actorId },
      { "data.userId": actorId },
      { "data.actorId": actorId },
      { "data.sessionId": actorId }
    );
  }

  return conditions;
};

const getFileExtension = (fileName) => {
  const name = String(fileName || "");
  const parts = name.split(".");
  return parts.length > 1 ? lower(parts.pop()) : "";
};

const buildAlert = (event, message, severity) => ({
  userId: event.userId,
  websiteId: event.websiteId,
  message,
  severity,
  standards: getStandards("SECURITY_MONITORING"),
  createdAt: new Date()
});

const detectImpossibleTravel = async (event) => {
  // Rule A: a user should not log in from two different countries within 2 hours.
  if (event.eventType !== "login" && event.eventType !== "login_success") {
    return null;
  }

  const previousLogin = await Event.findOne({
    apiKey: event.apiKey,
    websiteId: event.websiteId,
    _id: { $ne: event._id },
    eventType: { $in: ["login", "login_success"] },
    createdAt: { $gte: new Date(event.createdAt.getTime() - TWO_HOURS_MS) }
  })
    .sort({ createdAt: -1 })
    .select("location createdAt")
    .lean();

  if (!previousLogin?.location || !event.location) {
    return null;
  }

  const previousCountry = getCountryFromLocation(previousLogin.location);
  const currentCountry = getCountryFromLocation(event.location);

  if (previousCountry && currentCountry && previousCountry !== currentCountry) {
    return buildAlert(
      event,
      `Impossible travel detected: login from ${previousLogin.location} followed by ${event.location} within 2 hours`,
      "high"
    );
  }

  return null;
};

const detectBruteForce = async (event) => {
  // Rule B: repeated failed logins in a short window indicate brute force activity.
  if (event.eventType !== "failed_login") {
    return null;
  }

  const since = new Date(event.createdAt.getTime() - ONE_MINUTE_MS);
  const failedCount = await Event.countDocuments({
    websiteId: event.websiteId,
    eventType: "failed_login",
    createdAt: { $gte: since }
  });

  if (failedCount >= BRUTE_FORCE_THRESHOLD) {
    return buildAlert(
      event,
      `Brute force suspected: ${failedCount} failed login attempts in 1 minute`,
      "high"
    );
  }

  return null;
};

const detectRateAbuse = async (event) => {
  // Rule C: a very high volume of requests for one actor indicates likely rate limit abuse.
  const since = new Date(event.createdAt.getTime() - ONE_MINUTE_MS);
  const actorId = getActorId(event);
  const eventCount = await Event.countDocuments({
    websiteId: event.websiteId,
    $or: buildActorScope(event, actorId),
    createdAt: { $gte: since }
  });

  if (eventCount >= RATE_LIMIT_THRESHOLD) {
    return buildAlert(
      event,
      `Rate limiting violation detected: ${eventCount} requests observed in 1 minute for actor ${actorId}`,
      "high"
    );
  }

  return null;
};

const detectMalwareRisk = async (event) => {
  const eventType = lower(event.eventType);
  const appName = lower(event.data?.appName || event.data?.softwareName || event.data?.downloadName);
  const source = lower(event.data?.source || event.data?.downloadSource || event.data?.packageSource);
  const threatName = lower(event.data?.threatName || event.data?.antivirusResult || event.data?.malwareFamily);

  const installLikeEvent = [
    "software_install",
    "app_install",
    "endpoint_app_install",
    "download",
    "software_download"
  ].includes(eventType);

  if (!installLikeEvent) {
    return null;
  }

  if (
    event.data?.malwareDetected === true ||
    event.data?.isCracked === true ||
    hasAnyKeyword(appName, RISKY_SOFTWARE_KEYWORDS) ||
    hasAnyKeyword(source, RISKY_SOFTWARE_KEYWORDS) ||
    threatName
  ) {
    return buildAlert(
      event,
      `Malware risk detected: suspicious software activity for ${event.data?.appName || event.data?.softwareName || "unknown application"}`,
      "high"
    );
  }

  return null;
};

const detectMaliciousFileUpload = async (event) => {
  const eventType = lower(event.eventType);

  if (!["file_upload", "upload_attempt", "file_upload_attempt"].includes(eventType)) {
    return null;
  }

  const fileName = event.data?.fileName || event.data?.originalName || "";
  const extension = getFileExtension(fileName);
  const actualExtension = lower(event.data?.actualExtension || event.data?.detectedExtension);
  const mimeType = lower(event.data?.mimeType || event.data?.contentType);
  const detectedMime = lower(event.data?.detectedMime || event.data?.sniffedMime);

  const disguisedExecutable = DOCUMENT_EXTENSIONS.includes(extension) && (
    EXECUTABLE_EXTENSIONS.includes(actualExtension) ||
    mimeType.includes("application/x-msdownload") ||
    detectedMime.includes("application/x-msdownload") ||
    mimeType.includes("application/x-dosexec") ||
    detectedMime.includes("application/x-dosexec") ||
    event.data?.isExecutable === true
  );

  if (event.data?.malwareDetected === true || disguisedExecutable) {
    return buildAlert(
      event,
      `Malicious file upload blocked: ${fileName || "unknown file"} appears to be unsafe`,
      "high"
    );
  }

  return null;
};

const runDetection = async (event) => {
  // Run rules concurrently so tracking requests are not blocked by sequential checks.
  const candidates = await Promise.all([
    detectImpossibleTravel(event),
    detectBruteForce(event),
    detectRateAbuse(event),
    detectMalwareRisk(event),
    detectMaliciousFileUpload(event)
  ]);
  const alerts = candidates.filter(Boolean);

  if (!alerts.length) {
    return [];
  }

  return Alert.insertMany(alerts);
};

module.exports = {
  runDetection
};

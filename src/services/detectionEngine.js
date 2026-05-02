const Alert = require("../models/Alert");
const Event = require("../models/Event");
const { getStandards } = require("../config/securityStandards");
const { getCountryFromLocation } = require("./locationService");

const TWO_HOURS_MS = 2 * 60 * 60 * 1000;
const ONE_MINUTE_MS = 60 * 1000;

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

  if (failedCount > 20) {
    return buildAlert(
      event,
      `Brute force suspected: ${failedCount} failed login attempts in 1 minute`,
      "high"
    );
  }

  return null;
};

const detectRateAbuse = async (event) => {
  // Rule C: a very high volume of events for one API key indicates automation abuse.
  const since = new Date(event.createdAt.getTime() - ONE_MINUTE_MS);
  const eventCount = await Event.countDocuments({
    websiteId: event.websiteId,
    createdAt: { $gte: since }
  });

  if (eventCount > 500) {
    return buildAlert(
      event,
      `Rate abuse suspected: ${eventCount} events received in 1 minute`,
      "medium"
    );
  }

  return null;
};

const runDetection = async (event) => {
  // Run rules concurrently so tracking requests are not blocked by sequential checks.
  const candidates = await Promise.all([
    detectImpossibleTravel(event),
    detectBruteForce(event),
    detectRateAbuse(event)
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

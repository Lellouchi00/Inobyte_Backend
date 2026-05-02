const Alert = require("../models/Alert");
const Event = require("../models/Event");

const RANGE_MAP = {
  "1h": 60 * 60 * 1000,
  "24h": 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000,
  "30d": 30 * 24 * 60 * 60 * 1000
};

const getRangeStart = (range = "24h") => {
  const duration = RANGE_MAP[range] || RANGE_MAP["24h"];
  return new Date(Date.now() - duration);
};

const getBucketFormat = (range = "24h") => {
  if (range === "1h") return "%Y-%m-%d %H:%M";
  if (range === "24h") return "%Y-%m-%d %H:00";
  return "%Y-%m-%d";
};

const normalizeLimit = (value, fallback = 10, max = 50) => {
  const parsed = Number(value);

  if (!Number.isInteger(parsed) || parsed <= 0) return fallback;
  return Math.min(parsed, max);
};

const buildMatch = ({ userId, websiteId }, since) => ({
  userId,
  websiteId,
  createdAt: { $gte: since }
});

const getOverview = async (scope, since) => {
  const [eventsCount, alertsCount, highAlertsCount, activeSessions] = await Promise.all([
    Event.countDocuments(buildMatch(scope, since)),
    Alert.countDocuments(buildMatch(scope, since)),
    Alert.countDocuments({ ...buildMatch(scope, since), severity: "high" }),
    Event.distinct("ip", buildMatch(scope, since))
  ]);

  const securityScore = Math.max(0, Math.min(100, 100 - highAlertsCount * 12 - alertsCount * 3));

  return {
    securityScore,
    securityLabel: securityScore >= 80 ? "GOOD" : securityScore >= 60 ? "REVIEW" : "CRITICAL",
    totalEvents: eventsCount,
    totalAlerts: alertsCount,
    highAlerts: highAlertsCount,
    activeSessions: activeSessions.filter(Boolean).length
  };
};

const getEventTimeline = (scope, since, range) => Event.aggregate([
  { $match: buildMatch(scope, since) },
  {
    $group: {
      _id: {
        $dateToString: {
          format: getBucketFormat(range),
          date: "$createdAt"
        }
      },
      count: { $sum: 1 }
    }
  },
  { $sort: { _id: 1 } },
  {
    $project: {
      _id: 0,
      bucket: "$_id",
      count: 1
    }
  }
]);

const getEventTypeBreakdown = (scope, since) => Event.aggregate([
  { $match: buildMatch(scope, since) },
  { $group: { _id: "$eventType", count: { $sum: 1 } } },
  { $sort: { count: -1 } },
  { $limit: 12 },
  { $project: { _id: 0, eventType: "$_id", count: 1 } }
]);

const getSeverityBreakdown = (scope, since) => Alert.aggregate([
  { $match: buildMatch(scope, since) },
  { $group: { _id: "$severity", count: { $sum: 1 } } },
  { $project: { _id: 0, severity: "$_id", count: 1 } }
]);

const getGeoDistribution = (scope, since) => Event.aggregate([
  {
    $match: {
      ...buildMatch(scope, since),
      location: { $nin: [null, ""] }
    }
  },
  { $group: { _id: "$location", count: { $sum: 1 } } },
  { $sort: { count: -1 } },
  { $limit: 10 },
  { $project: { _id: 0, location: "$_id", count: 1 } }
]);

const getTopPages = (scope, since) => Event.aggregate([
  {
    $match: {
      ...buildMatch(scope, since),
      "data.currentUrl": { $nin: [null, ""] }
    }
  },
  { $group: { _id: "$data.currentUrl", count: { $sum: 1 } } },
  { $sort: { count: -1 } },
  { $limit: 10 },
  { $project: { _id: 0, url: "$_id", count: 1 } }
]);

const getRecentEvents = (scope, since, limit) => Event.find(buildMatch(scope, since))
  .sort({ createdAt: -1 })
  .limit(limit)
  .select("eventType data.currentUrl location ip userAgent createdAt")
  .lean();

const getRecentAlerts = (scope, since, limit) => Alert.find(buildMatch(scope, since))
  .sort({ createdAt: -1 })
  .limit(limit)
  .select("message severity standards createdAt")
  .lean();

const getVisualizationDashboard = async ({ userId, websiteId, range = "24h", limit }) => {
  const since = getRangeStart(range);
  const normalizedLimit = normalizeLimit(limit);
  const scope = { userId, websiteId };

  const [
    overview,
    eventTimeline,
    eventTypeBreakdown,
    severityBreakdown,
    geoDistribution,
    topPages,
    recentEvents,
    recentAlerts
  ] = await Promise.all([
    getOverview(scope, since),
    getEventTimeline(scope, since, range),
    getEventTypeBreakdown(scope, since),
    getSeverityBreakdown(scope, since),
    getGeoDistribution(scope, since),
    getTopPages(scope, since),
    getRecentEvents(scope, since, normalizedLimit),
    getRecentAlerts(scope, since, normalizedLimit)
  ]);

  return {
    range,
    since,
    generatedAt: new Date(),
    overview,
    charts: {
      eventTimeline,
      eventTypeBreakdown,
      severityBreakdown,
      geoDistribution,
      topPages
    },
    liveFeed: recentEvents.map((event) => ({
      id: event._id,
      eventType: event.eventType,
      url: event.data?.currentUrl || null,
      location: event.location,
      ip: event.ip,
      userAgent: event.userAgent,
      createdAt: event.createdAt
    })),
    alerts: recentAlerts
  };
};

module.exports = {
  getVisualizationDashboard
};

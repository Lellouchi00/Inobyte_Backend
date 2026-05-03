const Alert = require("../models/Alert");
const Event = require("../models/Event");
const Website = require("../models/Website");

const DAY_MS = 24 * 60 * 60 * 1000;

const getRiskLevel = (securityScore) => {
  if (securityScore >= 80) return "low";
  if (securityScore >= 60) return "medium";
  return "high";
};

const calculateSecurityScore = ({ high = 0, medium = 0, low = 0 }) => Math.max(
  0,
  100 - high * 15 - medium * 10 - low * 5
);

const getWebsiteForUser = async (userId, websiteId) => {
  const query = { userId };

  if (websiteId) {
    query._id = websiteId;
  }

  return Website.findOne(query).select("_id userId domain apiKey verified").lean();
};

exports.getDashboard = async (req, res) => {
  try {
    const website = await getWebsiteForUser(req.user.id, req.query.websiteId);

    if (!website) {
      return res.status(404).json({ msg: "Website not found" });
    }

    const since = new Date(Date.now() - DAY_MS);
    const scope = {
      userId: website.userId,
      websiteId: website._id
    };
    const recentScope = {
      ...scope,
      createdAt: { $gte: since }
    };

    const [
      totalEvents,
      alertsToday,
      severityCounts,
      liveEvents,
      alerts,
      eventsOverTime,
      alertsBySeverity
    ] = await Promise.all([
      Event.countDocuments(scope),
      Alert.countDocuments(recentScope),
      Alert.aggregate([
        { $match: recentScope },
        { $group: { _id: "$severity", count: { $sum: 1 } } }
      ]),
      Event.find(scope)
        .sort({ createdAt: -1 })
        .limit(20)
        .select("websiteId eventType data ip location userAgent createdAt")
        .lean(),
      Alert.find(scope)
        .sort({ createdAt: -1 })
        .limit(10)
        .select("websiteId message userTitle technicalTitle severity createdAt")
        .lean(),
      Event.aggregate([
        { $match: recentScope },
        {
          $group: {
            _id: {
              $dateToString: {
                format: "%H:00",
                date: "$createdAt"
              }
            },
            count: { $sum: 1 }
          }
        },
        { $sort: { _id: 1 } },
        { $project: { _id: 0, time: "$_id", count: 1 } }
      ]),
      Alert.aggregate([
        { $match: recentScope },
        { $group: { _id: "$severity", count: { $sum: 1 } } },
        { $project: { _id: 0, severity: "$_id", count: 1 } }
      ])
    ]);

    const severityMap = severityCounts.reduce((acc, item) => {
      acc[item._id] = item.count;
      return acc;
    }, {});
    const securityScore = calculateSecurityScore({
      high: severityMap.high,
      medium: severityMap.medium,
      low: severityMap.low
    });

    res.json({
      website: {
        id: website._id,
        domain: website.domain,
        verified: website.verified
      },
      summary: {
        totalEvents,
        alertsToday,
        securityScore,
        riskLevel: getRiskLevel(securityScore)
      },
      liveEvents,
      alerts: alerts.map((alert) => ({
        id: alert._id,
        websiteId: alert.websiteId,
        message: alert.message,
        userTitle: alert.userTitle,
        technicalTitle: alert.technicalTitle,
        severity: alert.severity,
        timestamp: alert.createdAt
      })),
      charts: {
        eventsOverTime,
        alertsBySeverity
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
};

exports.getAlerts = async (req, res) => {
  try {
    const website = await getWebsiteForUser(req.user.id, req.query.websiteId);

    if (!website) {
      return res.status(404).json({ msg: "Website not found" });
    }

    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 50;
    const skip = (page - 1) * limit;

    const scope = {
      userId: website.userId,
      websiteId: website._id
    };

    const alerts = await Alert.find(scope)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .select("websiteId message userTitle technicalTitle severity createdAt")
      .lean();

    const total = await Alert.countDocuments(scope);

    res.json({
      alerts: alerts.map((alert) => ({
        id: alert._id,
        websiteId: alert.websiteId,
        message: alert.message,
        userTitle: alert.userTitle,
        technicalTitle: alert.technicalTitle,
        severity: alert.severity,
        timestamp: alert.createdAt
      })),
      pagination: {
        total,
        page,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
};

exports.deleteAlert = async (req, res) => {
  try {
    const alertId = req.params.id;

    const alert = await Alert.findOneAndDelete({ 
      _id: alertId, 
      userId: req.user.id 
    });

    if (!alert) {
      return res.status(404).json({ msg: "Alert not found or unauthorized" });
    }

    res.json({ msg: "Alert deleted successfully", id: alertId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
};

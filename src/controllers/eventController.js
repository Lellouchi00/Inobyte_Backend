const Event = require("../models/Event");
const Website = require("../models/Website");
const { runDetection } = require("../services/detectionEngine");
const { getLocationFromIp } = require("../services/locationService");
const { emitToUser } = require("../socket");
const { getClientIp } = require("../utils/ip");

const MAX_EVENT_TYPE_LENGTH = 80;
const MAX_DATA_SIZE = 16 * 1024;

const isPlainObject = (value) => Boolean(value) && typeof value === "object" && !Array.isArray(value);

const normalizeEventType = (eventType) => String(eventType || "").trim().slice(0, MAX_EVENT_TYPE_LENGTH);

const validatePayload = ({ apiKey, eventType, data }) => {
  if (!apiKey || typeof apiKey !== "string") {
    return "API key is required";
  }

  if (!eventType || typeof eventType !== "string") {
    return "Event type is required";
  }

  if (!isPlainObject(data)) {
    return "Event data must be an object";
  }

  if (Buffer.byteLength(JSON.stringify(data), "utf8") > MAX_DATA_SIZE) {
    return "Event data is too large";
  }

  return null;
};

exports.trackEvent = async (req, res) => {
  try {
    const { apiKey, eventType, data = {} } = req.body;
    const validationError = validatePayload({ apiKey, eventType, data });

    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    const website = await Website.findOne({ apiKey })
      .select("_id userId apiKey domain verified")
      .lean();

    if (!website) {
      return res.status(403).json({ error: "Invalid API Key" });
    }

    // Only public IPs are used for GeoIP. Private and localhost addresses are ignored.
    const publicIp = getClientIp(req);
    const location = publicIp ? getLocationFromIp(publicIp) : null;
    const userAgent = String(req.headers["user-agent"] || data.userAgent || "").slice(0, 512);
    const createdAt = new Date();

    const event = await Event.create({
      userId: website.userId,
      websiteId: website._id,
      apiKey,
      eventType: normalizeEventType(eventType),
      data: {
        ...data,
        timestamp: data.timestamp || createdAt.toISOString()
      },
      ip: publicIp,
      location,
      userAgent,
      createdAt
    });

    // Detection can return zero or more alerts generated from the saved event.
    const alerts = await runDetection(event);
    const userRoom = String(website.userId);
    const eventData = {
      id: event._id,
      websiteId: event.websiteId,
      eventType: event.eventType,
      data: event.data,
      ip: event.ip,
      location: event.location,
      userAgent: event.userAgent,
      createdAt: event.createdAt
    };

    emitToUser(userRoom, "new_event", eventData);

    for (const alert of alerts) {
      emitToUser(userRoom, "new_alert", {
        id: alert._id,
        message: alert.message,
        userTitle: alert.userTitle,
        technicalTitle: alert.technicalTitle,
        severity: alert.severity,
        timestamp: alert.createdAt
      });
    }

    res.status(201).json({
      message: "Event saved",
      eventId: event._id,
      websiteId: event.websiteId,
      location,
      alerts: alerts.map((alert) => ({
        id: alert._id,
        message: alert.message,
        userTitle: alert.userTitle,
        technicalTitle: alert.technicalTitle,
        severity: alert.severity,
        timestamp: alert.createdAt
      }))
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
};

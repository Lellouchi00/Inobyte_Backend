const User = require("../models/User");
const Event = require("../models/Event");
const mongoose = require("mongoose");

const FIFTEEN_MINUTES = 15 * 60 * 1000;
const ONE_DAY = 24 * 60 * 60 * 1000;

const flaggedWords = ["alert", "critical", "failed", "flagged", "suspicious", "unusual", "risk"];

const asDate = (value) => (value ? new Date(value) : null);

const maskUserId = (user) => {
  const source = user.apiKey || user._id?.toString() || user.email || "0000";
  return `User ••${source.slice(-4)}`;
};

const getEventData = (event) => event?.data || {};

const getLocation = (event) => {
  const data = getEventData(event);

  if (data.location) return data.location;
  if (data.city && data.country) return `${data.city}, ${data.country}`;
  if (data.country) return data.country;
  if (event?.ip) return event.ip;

  return "Unknown";
};

const isFlaggedEvent = (event) => {
  const data = getEventData(event);
  const text = `${event?.eventType || ""} ${data.severity || ""} ${data.status || ""}`.toLowerCase();

  return data.flagged === true || flaggedWords.some((word) => text.includes(word));
};

const getEventTitle = (event) => {
  const data = getEventData(event);
  return data.title || data.message || event.eventType || "Activity recorded";
};

const getUserStatus = (lastEvent) => {
  if (!lastEvent) return "inactive";

  const lastSeen = asDate(lastEvent.createdAt);
  const age = Date.now() - lastSeen.getTime();

  if (age <= FIFTEEN_MINUTES) return "active";
  if (age <= ONE_DAY) return "idle";
  return "inactive";
};

const formatTime = (date) => {
  if (!date) return null;

  return new Intl.DateTimeFormat("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    hour12: false
  }).format(date);
};

const formatDay = (date) => {
  if (!date) return null;

  const today = new Date();
  if (date.toDateString() === today.toDateString()) return "Today";

  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric"
  }).format(date);
};

const relativeTime = (date) => {
  if (!date) return null;

  const diff = Date.now() - date.getTime();
  const minutes = Math.max(1, Math.floor(diff / (60 * 1000)));

  if (minutes < 60) return `${minutes}m ago`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;

  const days = Math.floor(hours / 24);
  return `${days}d ago`;
};

const toLiveEvent = (event) => {
  const createdAt = asDate(event.createdAt);
  const flagged = isFlaggedEvent(event);

  return {
    id: event._id,
    apiKey: event.apiKey,
    title: getEventTitle(event),
    eventType: event.eventType,
    location: getLocation(event),
    flagged,
    severity: flagged ? "critical" : "normal",
    createdAt,
    time: formatTime(createdAt),
    relativeTime: relativeTime(createdAt)
  };
};

const buildUserSummary = (user, events) => {
  const lastEvent = events[0] || null;
  const firstEvent = events[events.length - 1] || null;
  const flaggedEvents = events.filter(isFlaggedEvent);
  const lastSeen = asDate(lastEvent?.createdAt);
  const firstSeen = asDate(firstEvent?.createdAt || user.createdAt);
  const status = getUserStatus(lastEvent);
  const flagged = flaggedEvents.length > 0;

  return {
    id: user._id,
    email: user.email,
    apiKey: user.apiKey,
    displayName: maskUserId(user),
    location: getLocation(lastEvent),
    status,
    flagged,
    riskLevel: flagged ? "review" : status,
    totalEvents: events.length,
    flaggedEvents: flaggedEvents.length,
    firstSeen,
    firstSeenLabel: formatDay(firstSeen),
    lastSeen,
    lastSeenLabel: formatDay(lastSeen),
    lastActive: relativeTime(lastSeen)
  };
};

const loadUsersWithEvents = async (ownerId) => {
  const userQuery = ownerId ? { _id: ownerId } : {};
  const users = await User.find(userQuery).sort({ createdAt: -1 });
  const apiKeys = users.map((user) => user.apiKey).filter(Boolean);
  const events = await Event.find({ apiKey: { $in: apiKeys } }).sort({ createdAt: -1 });
  const eventsByApiKey = new Map();

  for (const event of events) {
    if (!eventsByApiKey.has(event.apiKey)) {
      eventsByApiKey.set(event.apiKey, []);
    }

    eventsByApiKey.get(event.apiKey).push(event);
  }

  return users.map((user) => ({
    user,
    events: eventsByApiKey.get(user.apiKey) || []
  }));
};

exports.getDashboard = async (req, res) => {
  try {
    const usersWithEvents = await loadUsersWithEvents(req.user?.id);
    const totalUsers = usersWithEvents.length;
    const now = Date.now();
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);

    const activeNow = usersWithEvents.filter(({ events }) => {
      const lastEvent = events[0];
      return lastEvent && now - asDate(lastEvent.createdAt).getTime() <= FIFTEEN_MINUTES;
    }).length;

    const todayEvents = await Event.find({ createdAt: { $gte: startOfDay } });
    const alertsToday = todayEvents.filter(isFlaggedEvent).length;
    const latestEvents = await Event.find().sort({ createdAt: -1 }).limit(6);
    const totalEvents = await Event.countDocuments();
    const criticalUsers = usersWithEvents.filter(({ events }) => events.some(isFlaggedEvent)).length;
    const securityScore = Math.max(0, Math.min(100, 100 - criticalUsers * 8 - alertsToday * 3));

    res.json({
      securityScore,
      securityLabel: securityScore >= 80 ? "GOOD" : securityScore >= 60 ? "REVIEW" : "CRITICAL",
      totalUsers,
      activeNow,
      alertsToday,
      totalEvents,
      liveIntelligence: latestEvents.map(toLiveEvent)
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
};

exports.getUsers = async (req, res) => {
  try {
    const { search = "", status = "all", flagged } = req.query;
    const normalizedSearch = search.trim().toLowerCase();
    const summaries = (await loadUsersWithEvents(req.user.id)).map(({ user, events }) => buildUserSummary(user, events));

    const filtered = summaries.filter((user) => {
      const matchesSearch = !normalizedSearch ||
        user.displayName.toLowerCase().includes(normalizedSearch) ||
        user.email?.toLowerCase().includes(normalizedSearch) ||
        user.location.toLowerCase().includes(normalizedSearch) ||
        user.apiKey?.toLowerCase().includes(normalizedSearch);
      const matchesStatus = status === "all" || user.status === status;
      const matchesFlagged = flagged === undefined || String(user.flagged) === String(flagged);

      return matchesSearch && matchesStatus && matchesFlagged;
    });

    res.json({
      totalScope: summaries.length,
      critical: summaries.filter((user) => user.flagged).length,
      monitoring: summaries.filter((user) => user.status === "active").length,
      users: filtered
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
};

exports.getUserDetails = async (req, res) => {
  try {
    const { identifier } = req.params;
    const query = mongoose.Types.ObjectId.isValid(identifier)
      ? { _id: req.user.id, $or: [{ apiKey: identifier }, { _id: identifier }] }
      : { _id: req.user.id, apiKey: identifier };
    const user = await User.findOne(query);

    if (!user) {
      return res.status(404).json({ msg: "User not found" });
    }

    const events = user.apiKey
      ? await Event.find({ apiKey: user.apiKey }).sort({ createdAt: -1 })
      : [];
    const summary = buildUserSummary(user, events);
    const flaggedEvents = events.filter(isFlaggedEvent);

    res.json({
      ...summary,
      eventHistory: events.map(toLiveEvent),
      riskAssessment: {
        level: flaggedEvents.length ? "moderate" : "low",
        summary: flaggedEvents.length
          ? "This user has flagged activity and should be reviewed before being cleared."
          : "No critical activity was found for this user based on the recorded events."
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
};

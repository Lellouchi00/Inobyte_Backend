const Event = require("../models/Event");
const User = require("../models/User");

exports.trackEvent = async (req, res) => {
  try {
    const { apiKey, eventType, data } = req.body;

    if (!apiKey || !eventType) {
      return res.status(400).json({ error: "API key and event type are required" });
    }

    const user = await User.findOne({ apiKey });

    if (!user) {
      return res.status(403).json({ error: "Invalid API Key" });
    }

    await Event.create({
      apiKey,
      eventType,
      data,
      ip: req.ip,
      userAgent: req.headers["user-agent"]
    });

    res.json({ message: "Event saved" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
};

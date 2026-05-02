const mongoose = require("mongoose");

const eventSchema = new mongoose.Schema({
  apiKey: String,
  eventType: String,
  data: Object,
  ip: String,
  userAgent: String
}, { timestamps: true });

module.exports = mongoose.model("Event", eventSchema);
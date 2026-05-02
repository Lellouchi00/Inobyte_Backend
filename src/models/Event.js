const mongoose = require("mongoose");

const eventSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
  websiteId: { type: mongoose.Schema.Types.ObjectId, ref: "Website", required: true, index: true },
  apiKey: { type: String, required: true, index: true },
  eventType: { type: String, required: true, index: true },
  data: Object,
  ip: String,
  location: String,
  userAgent: String
}, { timestamps: true });

eventSchema.index({ userId: 1, websiteId: 1, createdAt: -1 });
eventSchema.index({ websiteId: 1, eventType: 1, createdAt: -1 });
eventSchema.index({ apiKey: 1, eventType: 1, createdAt: -1 });

module.exports = mongoose.model("Event", eventSchema);

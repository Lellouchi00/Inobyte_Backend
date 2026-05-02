const mongoose = require("mongoose");

const reportSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    index: true
  },
  websiteId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Website",
    required: true,
    index: true
  },
  scanId: {
    type: String,
    required: true,
    index: true
  },
  scanType: {
    type: String,
    enum: ["manual", "daily_auto", "weekly_auto"],
    default: "manual"
  },
  targetUrl: {
    type: String,
    required: true
  },
  title: {
    type: String,
    required: true
  },
  description: String,
  summary: Object,
  threatsDetectedCount: {
    type: Number,
    default: 0
  },
  threatsDetected: {
    type: Array,
    default: []
  },
  overallRisk: {
    type: String,
    enum: ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
    default: "SAFE"
  },
  generatedAt: {
    type: Date,
    default: Date.now
  }
}, { timestamps: true });

reportSchema.index({ websiteId: 1, generatedAt: -1 });
reportSchema.index({ userId: 1, websiteId: 1, scanType: 1, createdAt: -1 });

module.exports = mongoose.model("Report", reportSchema);

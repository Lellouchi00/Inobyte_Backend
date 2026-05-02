const mongoose = require("mongoose");

const scanSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  websiteId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Website",
    index: true
  },
  url: String,
  status: { type: String, default: "pending" },
  scanType: {
    type: String,
    enum: ["manual", "daily_auto", "weekly_auto"],
    default: "manual"
  },
  results: Object
}, { timestamps: true });

module.exports = mongoose.model("Scan", scanSchema);

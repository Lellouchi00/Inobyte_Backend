const mongoose = require("mongoose");

const alertSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
  websiteId: { type: mongoose.Schema.Types.ObjectId, ref: "Website", index: true },
  message: String,
  userTitle: String,
  technicalTitle: String,
  severity: {
    type: String,
    enum: ["low", "medium", "high"],
    default: "low"
  },
  standards: Object
}, { timestamps: true });

alertSchema.index({ userId: 1, websiteId: 1, createdAt: -1 });

module.exports = mongoose.model("Alert", alertSchema);

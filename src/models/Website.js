const mongoose = require("mongoose");

const websiteSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    index: true
  },
  domain: {
    type: String,
    required: true,
    lowercase: true,
    trim: true
  },
  apiKey: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  verified: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
}, { timestamps: true });

websiteSchema.index({ userId: 1, domain: 1 }, { unique: true });

module.exports = mongoose.model("Website", websiteSchema);

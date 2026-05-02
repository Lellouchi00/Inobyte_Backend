const mongoose = require("mongoose");

const scanSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  url: String,
  status: { type: String, default: "pending" },
  results: Object
}, { timestamps: true });

module.exports = mongoose.model("Scan", scanSchema);
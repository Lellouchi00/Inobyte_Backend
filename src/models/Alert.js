const mongoose = require("mongoose");

const alertSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  message: String,
  severity: String
}, { timestamps: true });

module.exports = mongoose.model("Alert", alertSchema);
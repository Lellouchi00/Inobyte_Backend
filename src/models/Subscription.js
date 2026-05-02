const mongoose = require("mongoose");

const subSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  plan: String,
  status: String,
  stripeCustomerId: String
}, { timestamps: true });

module.exports = mongoose.model("Subscription", subSchema);
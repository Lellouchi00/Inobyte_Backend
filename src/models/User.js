
const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  apiKey: String,
  isVerified: { type: Boolean, default: false },
  otp: String,
  otpExpires: Date
}, { timestamps: true });

module.exports = mongoose.model("User", userSchema);
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const Event = require("../models/Event");
const generateOTP = require("../utils/generateOTP");
const transporter = require("../config/mailer");

exports.getUserDetails = async (req, res) => {
  try {
    const { apiKey } = req.params;
    const user = await User.findOne({ apiKey });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const events = await Event.find({ apiKey }).sort({ createdAt: -1 });

    res.json({
      email: user.email,
      events
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
};

exports.getUsers = async (req, res) => {
  try {
    const users = await User.find();
    const result = [];

    for (const user of users) {
      const lastEvent = await Event.findOne({ apiKey: user.apiKey }).sort({ createdAt: -1 });

      result.push({
        email: user.email,
        apiKey: user.apiKey,
        lastIP: lastEvent ? lastEvent.ip : null,
        lastActivity: lastEvent ? lastEvent.createdAt : null
      });
    }

    res.json(result);
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
};

exports.getDashboard = async (req, res) => {
  try {
    const totalEvents = await Event.countDocuments();
    const lastEvent = await Event.findOne().sort({ createdAt: -1 });

    res.json({
      totalEvents,
      lastActivity: lastEvent
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
};

exports.getUserData = async (req, res) => {
  try {
    const { apiKey } = req.query;
    const user = await User.findOne({ apiKey });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const events = await Event.find({ apiKey }).sort({ createdAt: -1 });
    const lastEvent = events[0];

    res.json({
      email: user.email,
      ip: lastEvent ? lastEvent.ip : "No data",
      events
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
};

exports.register = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ msg: "Email and password are required" });
    }

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(400).json({ msg: "User already exists" });
    }

    const hashed = await bcrypt.hash(password, 10);
    const otp = generateOTP();

    await User.create({
      email,
      password: hashed,
      otp,
      otpExpires: Date.now() + 10 * 60 * 1000
    });

    await transporter.sendMail({
      to: email,
      subject: "Verification Code",
      html: `<h2>${otp}</h2>`
    });

    res.json({ msg: "User created, check your email" });
  } catch (err) {
    console.error(err);

    if (err.code === 11000) {
      return res.status(400).json({ msg: "Email already exists" });
    }

    res.status(500).json({ msg: "Server error" });
  }
};

exports.verifyOTP = async (req, res) => {
  try {
    const { email, otp } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ msg: "User not found" });
    }

    if (String(user.otp) !== String(otp)) {
      return res.status(400).json({ msg: "Invalid OTP" });
    }

    if (user.otpExpires < Date.now()) {
      return res.status(400).json({ msg: "OTP expired" });
    }

    user.isVerified = true;
    user.otp = null;
    user.otpExpires = null;

    await user.save();

    res.json({ msg: "Email verified successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ msg: "User not found" });
    }

    if (!user.isVerified) {
      return res.status(400).json({ msg: "Verify your email first" });
    }

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(400).json({ msg: "Wrong password" });
    }

    if (!user.apiKey) {
      user.apiKey = "sk_" + crypto.randomUUID();
    }

    await user.save();

    const token = jwt.sign(
      { id: user._id, plan: user.plan },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || "7d" }
    );

    res.json({
      token,
      apiKey: user.apiKey,
      expiresIn: process.env.JWT_EXPIRES_IN || "7d"
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
};

exports.resendOTP = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ msg: "User not found" });
    }

    if (user.isVerified) {
      return res.status(400).json({ msg: "User is already verified" });
    }

    const otp = generateOTP();

    user.otp = otp;
    user.otpExpires = Date.now() + 10 * 60 * 1000;

    await user.save();

    await transporter.sendMail({
      to: email,
      subject: "New OTP Code",
      html: `<h2>Your new code: ${otp}</h2>`
    });

    res.json({ msg: "New OTP sent" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
};

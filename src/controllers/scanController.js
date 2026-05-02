const Scan = require("../models/Scan");
const Alert = require("../models/Alert");

exports.scanWebsite = async (req, res) => {
  try {
    const { url } = req.body;

    if (!url || typeof url !== "string") {
      return res.status(400).json({ msg: "URL is required" });
    }

    const results = {};

    if (!url.startsWith("https")) {
      results.https = "Missing HTTPS";
    }

    if (url.includes("test")) {
      results.warning = "Suspicious pattern";
    }

    const scan = await Scan.create({
      userId: req.user.id,
      url,
      status: "completed",
      results
    });

    if (results.https) {
      await Alert.create({
        userId: req.user.id,
        message: "Website not secure (HTTPS missing)",
        severity: "high"
      });
    }

    res.json(scan);
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
};

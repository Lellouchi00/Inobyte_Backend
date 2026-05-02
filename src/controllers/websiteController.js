const dns = require("node:dns/promises");
const Website = require("../models/Website");
const { generateApiKey } = require("../utils/apiKey");
const { isPrivateIp } = require("../utils/ip");

const normalizeDomain = (value) => {
  const raw = String(value || "").trim().toLowerCase();
  const withProtocol = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  const parsed = new URL(withProtocol);

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Only HTTP and HTTPS domains are supported");
  }

  if (parsed.hostname === "localhost" || isPrivateIp(parsed.hostname)) {
    throw new Error("Localhost and private IP ranges are not allowed");
  }

  return parsed.hostname;
};

const assertPublicDomain = async (domain) => {
  const records = await dns.lookup(domain, { all: true });

  if (!records.length) {
    throw new Error("Domain does not resolve");
  }

  if (records.some((record) => isPrivateIp(record.address))) {
    throw new Error("Domains resolving to private IP ranges are not allowed");
  }
};

exports.createWebsite = async (req, res) => {
  try {
    const domain = normalizeDomain(req.body.domain);
    await assertPublicDomain(domain);

    const website = await Website.create({
      userId: req.user.id,
      domain,
      apiKey: generateApiKey()
    });

    res.status(201).json({
      id: website._id,
      domain: website.domain,
      apiKey: website.apiKey,
      verified: website.verified,
      createdAt: website.createdAt
    });
  } catch (err) {
    if (err.code === 11000) {
      return res.status(409).json({ msg: "Website already exists for this user" });
    }

    if (
      err.message.includes("Invalid URL") ||
      err.message.includes("Only HTTP") ||
      err.message.includes("Localhost") ||
      err.message.includes("private IP") ||
      err.message.includes("resolve")
    ) {
      return res.status(400).json({ msg: err.message });
    }

    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
};

exports.listWebsites = async (req, res) => {
  try {
    const websites = await Website.find({ userId: req.user.id })
      .sort({ createdAt: -1 })
      .select("domain apiKey verified createdAt")
      .lean();

    res.json(websites.map((website) => ({
      id: website._id,
      domain: website.domain,
      apiKey: website.apiKey,
      verified: website.verified,
      createdAt: website.createdAt
    })));
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
};

exports.verifyWebsite = async (req, res) => {
  try {
    const { websiteId } = req.body;

    if (!websiteId) {
      return res.status(400).json({ msg: "websiteId is required" });
    }

    const website = await Website.findOneAndUpdate(
      { _id: websiteId, userId: req.user.id },
      { verified: true },
      { new: true }
    ).select("domain apiKey verified createdAt");

    if (!website) {
      return res.status(404).json({ msg: "Website not found" });
    }

    res.json({
      id: website._id,
      domain: website.domain,
      apiKey: website.apiKey,
      verified: website.verified,
      createdAt: website.createdAt
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
};

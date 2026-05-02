const router = require("express").Router();
const rateLimit = require("express-rate-limit");
const { trackEvent } = require("../controllers/eventController");

const eventLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 1200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many tracking requests" }
});

router.post("/track", eventLimiter, trackEvent);

module.exports = router;

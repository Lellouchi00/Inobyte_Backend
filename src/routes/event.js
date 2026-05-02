const router = require("express").Router();
const { trackEvent } = require("../controllers/eventController");

router.post("/track", trackEvent);

module.exports = router;

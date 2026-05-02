const router = require("express").Router();
const auth = require("../middleware/auth");
const website = require("../controllers/websiteController");

router.post("/", auth, website.createWebsite);
router.get("/", auth, website.listWebsites);
router.post("/verify", auth, website.verifyWebsite);

module.exports = router;

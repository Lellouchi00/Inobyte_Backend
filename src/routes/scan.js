const router = require("express").Router();
const auth = require("../middleware/auth");
const { scanWebsite } = require("../controllers/scanController");

router.post("/", auth, scanWebsite);

module.exports = router;
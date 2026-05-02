const router = require("express").Router();
const auth = require("../middleware/auth");
const ui = require("../controllers/uiController");

router.get("/", auth, ui.getUsers);
router.get("/:identifier", auth, ui.getUserDetails);

module.exports = router;

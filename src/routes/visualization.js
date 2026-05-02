const router = require("express").Router();
const auth = require("../middleware/auth");
const visualization = require("../controllers/visualizationController");

router.get("/dashboard", auth, visualization.getDashboard);

module.exports = router;

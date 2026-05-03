const router = require("express").Router();
const auth = require("../middleware/auth");
const dashboard = require("../controllers/dashboardController");

router.get("/", auth, dashboard.getDashboard);
router.get("/alerts", auth, dashboard.getAlerts);
router.delete("/alerts/:id", auth, dashboard.deleteAlert);

module.exports = router;

const router = require("express").Router();
const auth = require("../controllers/authController");

router.post("/register", auth.register);
router.post("/verify-otp", auth.verifyOTP);
router.post("/login", auth.login);
router.get("/dashboard", auth.getDashboard);
router.get("/users", auth.getUsers);
router.get("/users/:apiKey", auth.getUserDetails);

module.exports = router;

const router = require("express").Router();
const rateLimit = require("express-rate-limit");
const authMiddleware = require("../middleware/auth");
const auth = require("../controllers/authController");

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { msg: "Too many attempts, try again later" }
});

router.post("/register", authLimiter, auth.register);
router.post("/verify-otp", authLimiter, auth.verifyOTP);
router.post("/login", authLimiter, auth.login);
router.post("/resend-otp", authLimiter, auth.resendOTP);
router.get("/dashboard", authMiddleware, auth.getDashboard);
router.get("/users", authMiddleware, auth.getUsers);
router.get("/users/:apiKey", authMiddleware, auth.getUserDetails);

module.exports = router;

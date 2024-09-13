const express = require("express");
const authController = require("../../app/controllers/auth");
const { AuthController } = require("../../app/users");
const { auth, unAuth } = require("../../middlewares/userAuth/authMiddleware")
const router = express.Router();


router.get("/", authController.FirstRoute);

router.post("/signup", AuthController.signUp);
router.post("/signin", AuthController.signin);
router.post("/verify/phone-number", auth, AuthController.verifyPhoneNumber);
router.get("/sms/otp", auth, AuthController.generateSmsOtp);
router.post("/verify/otp", auth, AuthController.verifyOTP);
router.get("/google", AuthController.googleAuth);
router.get("/callback", AuthController.googleRedirect);
router.get("/authenticator/generate", auth, AuthController.generateAuthenticator);
router.post("/authenticator/validate", auth, AuthController.validateOtp);
router.get("/logout", auth, unAuth, AuthController.logout);

module.exports = {
  baseUrl: "/auth",
  router,
};
  
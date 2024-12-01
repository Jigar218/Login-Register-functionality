const express = require("express");
const {
  loginController,
  registerController,
  authController,
  forgotPasswordController,
  resetPasswordController,
  verifyOtpController,
  resendOtpController,
} = require("../controllers/userController");
const authMiddleware = require("../middlewares/authMiddleware");

//router object
const router = express.Router();

//routes
//LOGIN || POST
router.post("/login", loginController);

//REGISTER || POST
router.post("/register", registerController);

//Auth || POST
router.post("/getUserData", authMiddleware, authController);

// router.post("/email-send", emailSend);
router.post("/forgotPassword", forgotPasswordController);
router.post("/resetPassword", resetPasswordController);
router.post("/verifyotp", verifyOtpController);
router.post("/resendOtp", resendOtpController);
// router.post("/change-password", authController);

module.exports = router;

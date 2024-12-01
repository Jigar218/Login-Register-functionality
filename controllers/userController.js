const userModel = require("../models/userModels");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const crypto = require("crypto");
const nodemailer = require("nodemailer");
//register callback
// Register callback with password validation
const registerController = async (req, res) => {
  try {
    const { name, email, password, confirmPassword } = req.body;

    // Check if the email already exists
    const existingUser = await userModel.findOne({ email });
    if (existingUser) {
      return res
        .status(200)
        .send({ message: "User Already Exist", success: false });
    }

    // Check if password and confirmPassword match
    if (password !== confirmPassword) {
      return res
        .status(400)
        .send({ message: "Passwords do not match", success: false });
    }

    // Validate password complexity
    const passwordRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/;
    if (!passwordRegex.test(password)) {
      return res.status(400).send({
        message:
          "Password must be at least 6 characters long, include uppercase and lowercase letters, a number, and a special character.",
        success: false,
      });
    }

    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Save the new user
    const newUser = new userModel({ name, email, password: hashedPassword });
    await newUser.save();

    res.status(201).send({ message: "Register Successfully", success: true });
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: `Register Controller ${error.message}`,
    });
  }
};

// login callback
const loginController = async (req, res) => {
  try {
    const user = await userModel.findOne({ email: req.body.email });
    if (!user) {
      return res
        .status(400)
        .send({ message: "user not found", success: false });
    }
    const isMatch = await bcrypt.compare(req.body.password, user.password);
    if (!isMatch) {
      return res
        .status(401)
        .send({ message: "Invalid Email or Password", success: false });
    }
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });
    res.status(200).send({ message: "Login Success", success: true, token });
  } catch (error) {
    console.log(error);
    res.status(500).send({ message: `Error in Login CTRL ${error.message}` });
  }
};

const authController = async (req, res) => {
  try {
    const user = await userModel.findById({ _id: req.body.userId });
    user.password = undefined;
    if (!user) {
      return res.status(200).send({
        message: "user not found",
        success: false,
      });
    } else {
      res.status(200).send({
        success: true,
        data: user,
      });
    }
  } catch (error) {
    console.log(error);
    res.status(500).send({
      message: "auth error",
      success: false,
      error,
    });
  }
};

// Send OTP for reset password
const forgotPasswordController = async (req, res) => {
  try {
    const { email } = req.body;

    // Find the user by email
    const user = await userModel.findOne({ email });
    if (!user) {
      return res
        .status(404)
        .send({ message: "User not found", success: false });
    }

    // Generate a random OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
    const hashedOtp = crypto.createHash("sha256").update(otp).digest("hex");

    // Save the OTP and its expiry
    user.otp = hashedOtp;
    user.otpExpire = Date.now() + 10 * 60 * 1000; // 10 minutes expiration
    await user.save();

    // Send OTP via email
    const transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: {
        user: process.env.EMAIL, // Your email
        pass: process.env.EMAIL_PASSWORD, // Your email password or app password
      },
    });

    const mailOptions = {
      to: email,
      subject: "Password Reset OTP",
      text: `Your OTP for resetting your password is: ${otp}. This will expire in 10 minutes.`,
    };

    await transporter.sendMail(mailOptions);

    res.status(200).send({
      message: "Password reset OTP sent successfully",
      success: true,
    });
  } catch (error) {
    console.error(error);
    res.status(500).send({
      message: `Forgot Password Error: ${error.message}`,
      success: false,
    });
  }
};

// Verify OTP
const verifyOtpController = async (req, res) => {
  try {
    const { email, otp } = req.body;

    // Find the user by email
    const user = await userModel.findOne({ email });

    if (!user) {
      return res
        .status(404)
        .send({ message: "User not found", success: false });
    }

    // Hash the OTP and compare it with stored hashed OTP
    const hashedOtp = crypto.createHash("sha256").update(otp).digest("hex");

    // Check if the OTP is correct and not expired
    if (user.otp !== hashedOtp || user.otpExpire < Date.now()) {
      return res.status(400).send({
        message: "Invalid or expired OTP",
        success: false,
      });
    }

    // OTP is valid
    res.status(200).send({
      message: "OTP verified successfully",
      success: true,
    });
  } catch (error) {
    console.error(error);
    res.status(500).send({
      message: `Verify OTP Error: ${error.message}`,
      success: false,
    });
  }
};

// Reset password
const resetPasswordController = async (req, res) => {
  try {
    const { otp, newPassword, confirmNewPassword } = req.body;

    // Validate password complexity
    const passwordRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/;

    if (!passwordRegex.test(newPassword)) {
      return res.status(400).send({
        message:
          "Password must be at least 6 characters long, include uppercase and lowercase letters, a number, and a special character.",
        success: false,
      });
    }

    // Find the user by OTP
    const user = await userModel.findOne({
      otp: crypto.createHash("sha256").update(otp).digest("hex"),
      otpExpire: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).send({
        message: "Invalid or expired OTP",
        success: false,
      });
    }

    // Check if passwords match
    if (newPassword !== confirmNewPassword) {
      return res.status(400).send({
        message: "Passwords do not match",
        success: false,
      });
    }

    // Hash the new password and update it
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    user.otp = undefined; // Clear OTP after password reset
    user.otpExpire = undefined;
    await user.save();

    res.status(200).send({
      message: "Password reset successfully",
      success: true,
    });
  } catch (error) {
    console.error(error);
    res.status(500).send({
      message: `Reset Password Error: ${error.message}`,
      success: false,
    });
  }
};

const resendOtpController = async (req, res) => {
  try {
    const { email } = req.body;

    // Find the user by email
    const user = await userModel.findOne({ email });

    if (!user) {
      return res
        .status(404)
        .send({ message: "User not found", success: false });
    }

    // Ensure at least 1 minute has passed since the last OTP was sent
    const now = Date.now();
    const lastOtpSent = user.lastOtpSent || 0;

    if (now - lastOtpSent < 1 * 60 * 1000) {
      const waitTime = Math.ceil((1 * 60 * 1000 - (now - lastOtpSent)) / 1000);
      return res.status(400).send({
        message: `Please wait ${waitTime} seconds before requesting another OTP.`,
        success: false,
      });
    }

    // Generate a new OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedOtp = crypto.createHash("sha256").update(otp).digest("hex");

    // Save the OTP and its expiry
    user.otp = hashedOtp;
    user.otpExpire = now + 10 * 60 * 1000; // 10 minutes expiry
    user.lastOtpSent = now; // Track when this OTP was sent
    await user.save();

    // Send OTP via email
    const transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASSWORD,
      },
    });

    const mailOptions = {
      to: email,
      subject: "Resend OTP",
      text: `Your OTP for resetting your password is: ${otp}. This will expire in 10 minutes.`,
    };

    await transporter.sendMail(mailOptions);

    res.status(200).send({
      message: "OTP has been resent successfully",
      success: true,
    });
  } catch (error) {
    console.error(error);
    res.status(500).send({
      message: `Resend OTP Error: ${error.message}`,
      success: false,
    });
  }
};

module.exports = {
  loginController,
  registerController,
  authController,
  forgotPasswordController,
  resetPasswordController,
  verifyOtpController,
  resendOtpController,
};

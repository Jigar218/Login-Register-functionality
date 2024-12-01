const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, "name is require"],
  },
  email: {
    type: String,
    required: [true, "email is require"],
  },
  password: {
    type: String,
    required: [true, "password is require"],
  },
  resetPasswordToken: String,
  resetPasswordExpire: Date,
  otp: { type: String },
  otpExpire: { type: Date },
  lastOtpSent: { type: Date },
});

const userModel = mongoose.model("users", userSchema);

module.exports = userModel;

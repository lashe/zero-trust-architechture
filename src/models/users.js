const mongoose = require("mongoose");
const { Schema } = mongoose;
const UserSchema = new Schema({
  _id: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true
  },
  phoneNumber: {
    type: String,
    required: false
  },
  fullName: {
    type: String,
    required: false
  },
  gender: {
    type: Boolean,
    required: false,
  },
  otpSecret: {
    type: String,
    required: false,
    select: false
  },
  mfa: {
    type: Boolean,
    required: false,
    default: 0
  },
  mfaType: {
    type: String,
    required: false,
    enum: ["device", "sms"]
  },
  googleSignin: {
    type: Boolean,
    required: false,
    default: 0
  },
  isVerified: {
    type: Boolean,
    required: false,
    default: 0
  },
  isActive: {
    type: Boolean,
    required: false,
    default: 1
  },
  isDeleted: {
    type: Boolean,
    required: false,
    default: 0
  },
  acceptedTerms: {
    type: Boolean,
    required: true,
    default: 1
  },
  acceptedLocation: {
    type: Boolean,
    required: true,
    default: 1
  },
  password: {
    type: String,
    required: false,
    select: false
  },
  failedLoginAttempts: {
    type: Number,
    required: false,
    default: 0
  },
  lockUntil: { 
    type: Date 
  }
},
{
  toJSON: { virtuals: true },
  toObject: { virtuals: true },
  timestamps: true
},
{
  timestamps: true
});

const User = mongoose.model("User", UserSchema);

module.exports = {
  User
};
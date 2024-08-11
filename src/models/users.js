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
    required: true
  },
  fullName: {
    type: String,
    required: false
  },
  ageRange: {
    type: String,
    required: false
  },
  gender: {
    type: Boolean,
    required: false,
  },
  isVerified: {
    type: Boolean,
    required: false,
    default: 0
  },
  isActive: {
    type: Boolean,
    required: false,
    default: 0
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
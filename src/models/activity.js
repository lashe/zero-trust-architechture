const mongoose = require("mongoose");
const { Schema } = mongoose;
const ActivitySchema = new Schema({
  _id: {
    type: String,
    required: true,
  },
  userId: {
    type: String,
    required: true
  },
  body: {
    type: String,
    required: true
  },
  read: {
    type: Boolean,
    required: false,
    default: 0
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

const Activity = mongoose.model("Activity", ActivitySchema);

module.exports = {
  Activity
};
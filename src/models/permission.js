const mongoose = require("mongoose");
const { Schema } = mongoose;

const PermissionSchema = new Schema({
  _id: {
    type: String,
    required: true,
  },
  userId: {
    type: String,
    required: true
  },
  role: {
    type: String,
    required: false,
    default: "member"
    
  },
  permission: {
    type: Number,
    required: true,
    default: 0,
    enum: [0,1,2,3,4]
  }
},
{
  timestamps: true
});

const Permission = mongoose.model("Permission", PermissionSchema);

module.exports = {
  Permission
};
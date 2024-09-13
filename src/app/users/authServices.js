const { User } = require("../../models/users");
const { getOtp, verifyOtp } = require("../services/twilio");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = require("../../config/jwt");
const { generateOtp, verifyOTP } = require("../services/2factorauth");
var QRCode = require('qrcode');
const { addActivity } = require("../services/activity");
const { sendLoginNotification, sendLoginAttemptNotification } = require("../services/mailer");
const Logger = require("../../utils/logger");

const signIn = async (email, password) => {
    const MAX_FAILED_ATTEMPTS = 5;
    const LOCK_TIME = 2 * 60 * 60 * 1000; // 2 hours
    let isUser = await User.findOne({ email: email.toLowerCase() }).select("+password");

      if(!isUser) return null;

      if (isUser.lockUntil && isUser.lockUntil > Date.now()) return "locked";

      // compare hashed password against password from request body;
      let passwordIsValid = bcrypt.compareSync(
          password,
          isUser.password
        );
      if (!passwordIsValid) {
            // Increment failed attempts
            isUser.failedLoginAttempts += 1;

        // Lock the account if maximum attempts are exceeded
            if (isUser.failedLoginAttempts >= MAX_FAILED_ATTEMPTS) {
                isUser.lockUntil = Date.now() + LOCK_TIME;
                await isUser.save();
                await sendLoginAttemptNotification(isUser.email);
                return "locked";
            }
            await isUser.save();
            await addActivity(isUser.id, "Failed login attempt");
            return null;
        }
        
        // if(passwordIsValid && isUser.mfa === false) return "no mfa";
        isUser.failedLoginAttempts = 0;
        isUser.lockUntil = undefined;
        await isUser.save();
        await addActivity(isUser.id, "logged in");
        await sendLoginNotification(isUser.email);
        const data = getTempToken(isUser);
        let response = {
            isUser,
            data
        }
        return response;
}

const phoneNubmerVerification = async (id, phoneNumber) => {
    try {
        const isUser = await User.findOne({ phoneNumber: phoneNumber });
        if(isUser && !isUser.id !== id) return "exists";
        await User.updateOne({ _id: isUser.id }, {
          $set:{
            phoneNumber: phoneNumber
          }
        });
        getOtp(phoneNumber);
        return true;
    } catch (error) {
        Logger.error(error);
        return null;
    }
};

const getSmsOtp = async (id) => {
  try {
      const isUser = await User.findOne({ _id: id });
      if(isUser.mfaType && !isUser.mfaType == "sms") return false;
      if(!isUser.phoneNumber) return false;
      getOtp(isUser.phoneNumber);
      return true;
  } catch (error) {
      Logger.error(error);
      return null;
  }
};

const otpVerification = async (id, otp) => {
    const isUser = await User.findOne({ _id: id });
    if(!isUser) return false;
    if(isUser.mfaType && !isUser.mfaType == "sms") return false;
    if(!isUser.phoneNumber) return false;
    const verifyotpp = await verifyOtp(isUser.phoneNumber, otp);
    if (verifyotpp.status === "approved") {
      const data = getToken(isUser);
      if(isUser.mfaType && isUser.mfaType == "sms") {
        let response = {
          isUser,
          data
      };
      return response;
      }
      const updatedUser = await User.updateOne({ _id: isUser.id }, {
        $set:{
          mfa: 1, mfaType: "sms"
        }
      });
      let response = {
        updatedUser,
        data
    };
    return response;
    }
    Logger.error(verifyotpp.status);
    return false;
};

// generate OTP authenticator app secret string for installiation
const otpGenerator = async (userId) => {
    const user = await User.findOne({ _id: userId });
    if(!user) return null;
    if(user.mfa === true) return "exists";
    const generator = await generateOtp();
    await User.updateOne({_id: userId}, {
        $set: {
            otpSecret: generator.base32
        }
    });
    console.log(generator);
    const qrCode = QRCode.toDataURL(generator.otpauth_url, function(err, data_url) {       
        // Display this data URL to the user in an <img> tag
        // Example:
        // write('<img src="' + data_url + '">');
        return data_url;
      });
      let data = {
        otpPath: generator.otpauth_url,
        qrCode: qrCode
      }
    return data;
};

// validate authenticator app
const validateOTP = async (userId, otp) => {
    const user = await User.findOne({ _id: userId }).select("+otpSecret");
    if(!user) return null;
    const isValidated = await verifyOTP(user.otpSecret, otp);
    if (!isValidated) return false;
    let data;
    if(!user.mfa) {
        await User.updateOne({_id: userId}, { $set:{ mfa: 1, mfaType: "device" }});
        const updatedUser = await User.findOne({ _id: userId });
        data = getToken(updatedUser);
        let response = {
          updatedUser,
          data
      };
      return response;
    }
    data = getToken(user);
    let response = {
      user,
      data
  };
  return response;
};

// deregister a MFA authenticator app
const unvalidateOTP = async (userId, otp) => {
  const user = await User.findOne({ _id: userId, mfa: 1, mfaType: "device" });
  if(!user) return null;
  const isValidated = await verifyOTP(user.otpSecret, otp);
  if (!isValidated) return false;
  await User.updateOne({_id: userId}, { $set:{ mfa: 0, otpSecret: null }});
  return true;
};

// function for changing to a new password after validating the old password.
const passwordChange = async (userdId, oldPassword, newPassword) =>{
    const user = await User.findOne({ _id: userdId }).select(
        "+password"
      );
      const passwordIsValid = await bcrypt.compareSync(
        oldPassword,
        user.password
      );
      if (passwordIsValid) {
        const hashedPassword = bcrypt.hashSync(newPassword, 8);
        await User.updateOne({ _id: id },{ $set: { password: hashedPassword } });
        await addActivity(user.id, "changed password");
        return true;
      }
      return false;
};

// function for updsting user password
const passwordUpdate = async (id, newPassword) =>{
    const hashedPassword = bcrypt.hashSync(newPassword, 8);
    await User.updateOne({ _id: id },{ $set: { password: hashedPassword } });
    await addActivity(id, "reset password");
    return true;
};

// function for vlaidating refresh tokens
const refreshToken = async (token) => {
  jwt.verify(token, config.jwt_secret, async (err, decoded) => {
    if (err) {
      console.error(err);
      return "expired";
    }
    const user = await User.findOne({ where: { _id: decoded.id } });
    data = getToken(user);
    return data;
  });
};

// generate JWT token after authorisatioon has been validated
const getToken = (user) => {
    let token = jwt.sign(
      { id: user._id, email: user.email, mfa: user.mfa },
      config.jwt_secret,
      {
        expiresIn: "1h", // expires in 1 hour
      }
      // { algorithm: 'RS256' }
    );
    let refreshToken = jwt.sign({ id: user._id }, config.jwt_secret);
    let data = {
    token: token,
    refreshToken: refreshToken,
    token_type: "jwt",
    expiresIn: "1h",
  };
  return data;
  };

  // generate JWT token after authorisatioon has been validated
const getTempToken = (user) => {
  let token = jwt.sign(
    { id: user._id, email: user.email, mfa: user.mfa },
    config.jwt_secret,
    {
      expiresIn: 900000, // expires in 15 minutes
    }
    // { algorithm: 'RS256' }
  );
  let data = {
  token: token,
  token_type: "jwt",
  expiresIn: 900000,
};
return data;
};


module.exports = {
    phoneNubmerVerification,
    otpVerification,
    passwordChange,
    passwordUpdate,
    getToken,
    otpGenerator,
    validateOTP,
    unvalidateOTP,
    signIn,
    refreshToken,
    getTempToken,
    getSmsOtp
}
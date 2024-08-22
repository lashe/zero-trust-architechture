const { User } = require("../../models/users");
const { getOtp, verifyOtp } = require("../services/twilio");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = require("../../config/jwt");
const { generateOtp, verifyOTP } = require("../services/2factorauth");
var QRCode = require('qrcode');

const signIn = async (email, password) => {
    const isUser = await User.findOne({ email: email.toLowerCase() }).select(
        "+password"
      );

      if(!isUser) return false;

      // compare hashed password against password from request body;
      let passwordIsValid = bcrypt.compareSync(
          password,
          isUser.password
        );
        if (!passwordIsValid) return false;
        // if(passwordIsValid && isUser.mfa === false) return "no mfa";
        const data = getToken(isUser);
        let response = {
            isUser,
            data
        }
        return response;
}

const phoneNubmerVerification = async (phoneNumber) => {
    // if(!phoneNumber) return false;
    // return true;

    try {
        const verifyNumber = await getOtp(phoneNumber);
        return true;
    } catch (error) {
        console.error(error);
        return false;
    }
};

const otpVerification = async (phoneNumber, otp) => {
    // if(!phoneNumber && !otp) return false;
    // return true;
    const verifyotpp = await verifyOtp(phoneNumber, otp);
    if (verifyotpp.status === "approved") return true;
    console.error(verifyotpp.status);
    return false;
};

const otpGenerator = async (userId) => {
    const user = await User.findOne({ _id: userId });
    if(!user) return null;
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

const validateOTP = async (userId, otp) => {
    const user = await User.findOne({ _id: userId });
    if(!user) return null;
    const isValidated = await verifyOTP(user.otpSecret, otp);
    if (!isValidated) return false;
    let data;
    if(!user.mfa) {
        await User.updateOne({_id: userId}, { $set:{ mfa: 1, mfaType: "device" }});
        const updatedUser = await User.findOne({ _id: userId });
        data = getToken(updatedUser);
    }
    data = getToken(user);
    return data;
};

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
        return true;
      }
      return false;
};

const passwordUpdate = async (id, newPassword) =>{
    const hashedPassword = bcrypt.hashSync(newPassword, 8);
    await User.updateOne({ _id: id },{ $set: { password: hashedPassword } });
    return true;
};

const getToken = (user) => {
    let token = jwt.sign(
      { id: user._id, email: user.email, mfa: user.mfa },
      config.jwt_secret,
      {
        expiresIn: 2630000, // expires in 1 month
      }
    );
    let refreshToken = jwt.sign({ id: user._id, email: user.email, mfa: user.mfa }, config.jwt_secret);
    let data = {
    token: token,
    refreshToken: refreshToken,
    token_type: "jwt",
    expiresIn: 2630000,
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
    signIn
}
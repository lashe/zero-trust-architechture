const speakeasy = require("speakeasy");

const generateOtp = async () => {
    let secret = speakeasy.generateSecret({
        name: "ZTA Demo",
        length: 20,
      });
      return secret;
};

const verifyOTP = async ( otpSecret, otp ) => {
    let tokenValidates = speakeasy.totp.verify({
      secret: otpSecret,
      encoding: "base32",
      token: otp,
      window: 6,
    });

    return tokenValidates;
};

module.exports = {
    generateOtp,
    verifyOTP
}
const { TWILIO } = require("../../config/app");
const Logger = require("../../utils/logger");
const accountSid = TWILIO.ACCOUNT_SID;
const authToken = TWILIO.AUTH_TOKEN;
const serviceSid = TWILIO.VERIFY_SERVICE_SID;
const twilio = require("twilio")(accountSid, authToken);

const getOtp = (phone_number)=>{
  try {
    const sendOtp = twilio.verify.v2.services(serviceSid)
    .verifications
    .create({ to: phone_number, channel: "sms" });
    console.log(sendOtp);
  } catch (error) {
    Logger.error(error);
  }
};

const verifyOtp = async (phone_number, otp)=>{
  try {
    const verification = await twilio.verify.v2.services(serviceSid)
    .verificationChecks
    .create({ to: phone_number, code: otp });
  return verification;
  } catch (error) {
    Logger.error(error);
  }
};

module.exports = {
  getOtp,
  verifyOtp
};
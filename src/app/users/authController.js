const { jsonFailed, jsonS } = require("../../utils");
const { phoneNubmerVerification, otpVerification, passwordChange, passwordUpdate, otpGenerator, validateOTP, signIn, getToken } = require("./authServices");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = require("../../config/jwt");
const { User } = require("../../models/users");
const { googleVerify, googleAuthSignIn } = require("../services/google");
const { createNewUser, createNewUserGoogle } = require("./userServices");

let controller = {
  signUp: async (req, res) => {
    const { email, fullName, phoneNumber, password } = req.body;
    if (!email) return jsonFailed(res, {}, "No email Provided", 400);
    const newUser = { email, fullName, phoneNumber, password };
    const createUser = await createNewUser(newUser);
    console.log({returnedData: createUser});
    if (!createUser) return jsonFailed(res, {}, "Error Creating New User", 400);
    if(createUser === "exists")return jsonFailed(res, {}, "An account already exists with this email", 400);
    return jsonS(res, 201, "Successfully Created User");
},

    verifyPhoneNumber: async (req, res) => {
        const { phoneNumber } = req.body;
        const verifyNumber = await phoneNubmerVerification(phoneNumber);
        if(!verifyNumber) return jsonFailed(res, {}, "Error Verifying Phone Number", 400);
        return jsonS(res, 200, "Verification successfully sent");
    },

    verifyOTP: async (req, res) => {
        const { phoneNumber, otp } = req.body;
        const verifyOtp = await otpVerification(phoneNumber, otp);
        if(!verifyOtp) return jsonFailed(res, {}, "Error Verifying OTP", 400);
        return jsonS(res, 200, "Phone Number Susseccfully Verified");
    },

    signin: async (req, res) => {
      try {
        const { email, password } = req.body;
        const login = await signIn(email, password);
        if(!login) return jsonFailed(res, {}, "Invalid Credentials", 400);
          req.session.user = login.isUser;
        return jsonS(res, 200, "Successful", login.data);
      } catch (error) {
        console.error(error)
      }
    },

    googleAuth: async (req, res) => {
      const googleSignin = await googleAuthSignIn();
      req.session.state = googleSignin.state;
      res.redirect(googleSignin.authUrl);
    },

    googleRedirect: async (req, res) => {
      const { authuser, code, hd, prompt, scope, state} = req.query;
      // console.log(req.query);
      if (req.session.state === state) {
        const verifyIdtoken = await googleVerify(code);
      if (verifyIdtoken) {
        console.log("google", verifyIdtoken);
        const newUser = await createNewUserGoogle(verifyIdtoken);
        if(!newUser) return jsonFailed(res, {}, "Error: User cannot be added", 404);
        req.session.user = newUser;
          const data = getToken(newUser);
        return jsonS(res, 200, "success", data, {});
      }
      return jsonFailed(res, null, "error verifying google account", 400);
      }
      console.log("incorrect");
      return jsonFailed(res, null, "error verifying google account: unverrified attempt", 400);
    },

    generateAuthenticator: async (req, res) => {
      const { id } = req.user;
      const generateOTP = await otpGenerator(id);
      if(!generateOTP) return jsonFailed(res, {}, "Error: Auth Generator failed", 400);
      // write('<img src="' + generateOTP.qrCode + '">');
      return jsonS(res, 200, "success", generateOTP);
    },

    validateOtp: async (req, res) => {
      const { id } = req.user;
      const { otp } = req.body;
      const otpValidated = await validateOTP(id, otp);
      if(!otpValidated) return jsonFailed(res, {}, "Error: Unable to validate otp", 403);
      return jsonS(res, 200, "success", otpValidated);
    },

      changePassword: async (req, res) =>{
        const { id } = req.user;
        const { oldPassword, newPassword } = req.body;
        const changeUserPassword = await passwordChange(id, oldPassword, newPassword);
        if(changeUserPassword) return jsonS(res, 200, "Password Changed Susseccfully"); 
        if(!changeUserPassword) return jsonFailed(res, {}, "Password does not match", 400);
      },

      updatePassword: async (req, res) =>{
        const { id } = req.user;
        const { newPassword } = req.body;
        const updateUserPassword = await passwordUpdate(id, newPassword);
        if(updateUserPassword) return jsonS(res, 200, "Password Updated Susseccfully"); 
        if(!updateUserPassword) return jsonFailed(res, {}, "Password does not match", 400);
      }
}

module.exports = controller;
const { OAuth2Client } = require("google-auth-library");
const { GOOGLE } = require("../../config/app");
const { google } = require("googleapis");
const crypto = require("crypto");

const oauth2Client = new google.auth.OAuth2(
  GOOGLE.CLIENT_ID,
  GOOGLE.CLIENT_SECRET,
  "http://localhost:3000/api/v1/auth/callback"
);

const googleAuthSignIn = async () => {
  // generate state parameter
  const state = crypto.randomBytes(32).toString('hex');
  // generate authorization url for redirecting users to google sign up page
  const authorizationUrl = oauth2Client.generateAuthUrl({
    access_type: 'online',
  scope: 'profile email',
  // Enable incremental authorization. Recommended as a best practice.
  include_granted_scopes: true,
  // Include the state parameter to reduce the risk of CSRF attacks.
  state: state
  });
  let response = {
    authUrl: authorizationUrl,
    state
  };
  return response;
}

const client = new OAuth2Client(
  GOOGLE.CLIENT_ID, 
  GOOGLE.CLIENT_SECRET, 
  "http://localhost:3000/api/v1/auth/callback"
);

const googleVerify = async (code)=> {
  try {
    // validate code received from google for a token through the callback url
    const { tokens } = await client.getToken(code);

    // verify token received from code validation
    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: GOOGLE.CLIENT_ID
    });

    // extract users public information
    const payload = ticket.getPayload();
    const userid = payload["sub"];
  
    console.log(payload);
    return payload;
  } catch (error) {
    console.error(error);
  }
};

module.exports={
  googleVerify,
  googleAuthSignIn
};
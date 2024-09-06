// config.js
const dotenv = require("dotenv");
dotenv.config();

module.exports = {
  APP_NAME: process.env.APP_NAME,
  PORT: process.env.PORT,
  NODE_ENV: process.env.NODE_ENV,
  // Database Connection
  MONGO_DB: process.env.MONGO_DB,
  SESSION_SECRET: process.env.SESSION_SECRET,
  GOOGLE: {
    CLIENT_ID: process.env.GOOGLE_CLIENT_ID,
    CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET
  },
  TWILIO: {
    ACCOUNT_SID: process.env.ACCOUNT_SID,
    AUTH_TOKEN: process.env.AUTH_TOKEN,
    VERIFY_SERVICE_SID: process.env.VERIFY_SERVICE_SID
  },
  MAILER: {
    USERNAME: process.env.MAILER_USERNAME,
    PASSWORD: process.env.MAILER_PASS,
    HOST: process.env.MAILER_HOST
  },
  USER_SERVICE_URL: process.env.USER_SERVICE_URL
};

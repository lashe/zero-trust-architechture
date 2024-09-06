const nodeMailer = require("nodemailer");
const { MAILER } = require("../../config/app");

const transport = nodeMailer.createTransport({
    host: MAILER.HOST,
    port: 2525,
    auth: {
        user: MAILER.USERNAME,
        pass: MAILER.PASSWORD,
    },
});

const sendEmailNotification = async (email, subject, body) => {
    const mailOptions = {
        from: MAILER.USERNAME,
        to: email,
        subject: subject,
        text: body
    }

    try {
        await transport.sendMail(mailOptions);
        console.log("Email sent successfully!")
    } catch (error) {
        console.error("There was a problem sending the email", error)
    }
};

const sendLoginNotification = async (email) => {
    const mailOptions = {
        from: MAILER.USERNAME,
        to: email,
        subject: "Authorization",
        text: `you logged in at ${Date()}, if this wasn't you please contact admin or reset your password`
    }

    try {
        await transport.sendMail(mailOptions);
        console.log("Email sent successfully!")
    } catch (error) {
        console.error("There was a problem sending the email", error)
    }
};

const sendLoginAttemptNotification = async (email) => {
    const mailOptions = {
        from: MAILER.USERNAME,
        to: email,
        subject: "Authorization",
        text: "This is to inform you that your account has been locked due to several failed login attempts. please try again after a few minutes or reset your password if you have forgotten it. if this wasn't you please contact admin immediately or reset your password."
    }

    try {
        await transport.sendMail(mailOptions);
        console.log("Email sent successfully!")
    } catch (error) {
        console.error("There was a problem sending the email", error)
    }
};

module.exports = {
    sendEmailNotification,
    sendLoginNotification,
    sendLoginAttemptNotification
}
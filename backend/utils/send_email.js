const nodemailer = require("nodemailer");
const otpTemplate = require("./emailTemplates/otpTemplate");

const templates = {
  otp: otpTemplate,
};

const transport = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const sendEmail = async ({ to, subject, template, data }) => {
  try {
    console.log("Full payload:", { to, subject, template, data });

    if (!templates[template]) {
      throw new Error("Invalid email template");
    }

    const html = templates[template](data);

    await transport.sendMail({
      from: `"MyAuthApp" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      html,
    });

    console.log("Email sent successfully");
  } catch (error) {
    console.error("Email Error:", error.message);
    throw error;
  }
};

module.exports = sendEmail;

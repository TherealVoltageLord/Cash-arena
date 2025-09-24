const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransporter({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

exports.sendVerificationEmail = async (email, token) => {
  const verificationUrl = `${process.env.FRONTEND_URL}/verify/${token}`;
  
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Verify Your Cash Arena Account',
    html: `Click <a href="${verificationUrl}">here</a> to verify your account.`
  };

  await transporter.sendMail(mailOptions);
};

exports.sendPasswordResetEmail = async (email, token) => {
  const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
  
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Reset Your Cash Arena Password',
    html: `Click <a href="${resetUrl}">here</a> to reset your password. This link expires in 1 hour.`
  };

  await transporter.sendMail(mailOptions);
};
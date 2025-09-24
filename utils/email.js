const nodemailer = require('nodemailer');
const nodemailer = require('nodemailer');

// Create transporter 
const createTransporter = () => {
  return nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });
};

exports.sendVerificationEmail = async (email, token) => {
  try {
    const transporter = createTransporter();
    const verificationUrl = `${process.env.FRONTEND_URL}/verify/${token}`;
    
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Verify Your Cash Arena Account',
      html: `Click <a href="${verificationUrl}">here</a> to verify your account.`
    };

    await transporter.sendMail(mailOptions);
    return true;
  } catch (error) {
    console.error('Error sending verification email:', error);
    return false;
  }
};

exports.sendPasswordResetEmail = async (email, token) => {
  try {
    const transporter = createTransporter();
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
    
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Reset Your Cash Arena Password',
      html: `Click <a href="${resetUrl}">here</a> to reset your password.`
    };

    await transporter.sendMail(mailOptions);
    return true;
  } catch (error) {
    console.error('Error sending password reset email:', error);
    return false;
  }
};

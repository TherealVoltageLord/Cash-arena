const User = require('../models/User');
const PasswordReset = require('../models/PasswordReset');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { validationResult } = require('express-validator');
const { sendVerificationEmail, sendPasswordResetEmail } = require('../utils/email');

const generateTokens = (userId) => {
  const token = jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '15m' });
  const refreshToken = jwt.sign({ userId }, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });
  return { token, refreshToken };
};

const validateRegistration = (username, email, password) => {
  const errors = [];
  
  if (!username || username.length < 3) {
    errors.push('Username must be at least 3 characters');
  }
  
  if (!email || !/\S+@\S+\.\S+/.test(email)) {
    errors.push('Valid email is required');
  }
  
  if (!password || password.length < 6) {
    errors.push('Password must be at least 6 characters');
  }
  
  return errors;
};

exports.register = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        success: false,
        message: 'Validation failed', 
        errors: errors.array() 
      });
    }

    const { username, email, password, referredBy } = req.body;
    
    const validationErrors = validateRegistration(username, email, password);
    if (validationErrors.length > 0) {
      return res.status(400).json({ 
        success: false,
        message: 'Validation failed', 
        errors: validationErrors 
      });
    }
    
    const existingIP = await User.findOne({ lastIP: req.ip });
    if (existingIP) {
      return res.status(400).json({ 
        success: false,
        message: 'One account per IP address is allowed' 
      });
    }

    const existingEmail = await User.findOne({ email: email.toLowerCase() });
    if (existingEmail) {
      return res.status(400).json({ 
        success: false,
        message: 'Email already registered' 
      });
    }

    const existingUsername = await User.findOne({ 
      username: new RegExp(`^${username}$`, 'i') 
    });
    if (existingUsername) {
      return res.status(400).json({ 
        success: false,
        message: 'Username already taken' 
      });
    }

    const referralCode = crypto.randomBytes(4).toString('hex').toUpperCase();
    const emailVerificationToken = crypto.randomBytes(32).toString('hex');
    const emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);

    let referrer = null;
    if (referredBy) {
      referrer = await User.findOne({ referralCode: referredBy });
    }

    const user = new User({
      username: username.trim(),
      email: email.toLowerCase().trim(),
      password,
      referralCode,
      referredBy: referrer ? referredBy : undefined,
      emailVerificationToken,
      emailVerificationExpires,
      lastIP: req.ip
    });

    await user.save();

    if (referrer) {
      referrer.referrals.push({
        userId: user._id,
        username: user.username,
        joinedAt: new Date()
      });
      await referrer.save();
    }

    const emailSent = await sendVerificationEmail(user.email, emailVerificationToken);
    
    if (!emailSent) {
      console.warn('Verification email failed to send for user:', user.email);
    }

    res.status(201).json({ 
      success: true,
      message: 'Registration successful. Please check your email to verify your account.',
      userId: user._id,
      emailSent: emailSent
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error during registration' 
    });
  }
};

exports.login = async (req, res) => {
  try {
    const { emailOrUsername, password } = req.body;
    
    if (!emailOrUsername || !password) {
      return res.status(400).json({ 
        success: false,
        message: 'Email/username and password are required' 
      });
    }

    const user = await User.findOne({
      $or: [
        { email: emailOrUsername.toLowerCase() }, 
        { username: new RegExp(`^${emailOrUsername}$`, 'i') }
      ]
    });

    if (!user) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid credentials' 
      });
    }

    if (user.isLocked()) {
      const timeLeft = Math.ceil((user.lockUntil - Date.now()) / 60000);
      return res.status(400).json({ 
        success: false,
        message: `Account temporarily locked. Try again in ${timeLeft} minutes.` 
      });
    }

    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      user.incrementLoginAttempts();
      await user.save();
      
      const attemptsLeft = 5 - user.loginAttempts;
      return res.status(400).json({ 
        success: false,
        message: `Invalid credentials. ${attemptsLeft > 0 ? `${attemptsLeft} attempts remaining` : 'Account will be locked after next failed attempt'}` 
      });
    }

    if (!user.verified) {
      return res.status(400).json({ 
        success: false,
        message: 'Please verify your email before logging in' 
      });
    }

    if (user.suspended) {
      return res.status(400).json({ 
        success: false,
        message: `Account suspended. Reason: ${user.suspensionReason || 'Violation of terms'}` 
      });
    }

    user.resetLoginAttempts();
    user.lastLogin = new Date();
    user.lastIP = req.ip;
    await user.save();

    const tokens = generateTokens(user._id);
    
    res.json({ 
      success: true,
      ...tokens, 
      user: { 
        id: user._id, 
        username: user.username, 
        email: user.email,
        role: user.role,
        balance: user.balance,
        investment: user.investment,
        verified: user.verified,
        profile: user.profile,
        totalEarned: user.totalEarned,
        totalWithdrawn: user.totalWithdrawn,
        totalReferrals: user.referrals.length
      } 
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error during login' 
    });
  }
};

exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ 
        success: false,
        message: 'Email is required' 
      });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    
    if (!user) {
      return res.status(200).json({ 
        success: true,
        message: 'If this email exists in our system, a password reset link will be sent.' 
      });
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 1 * 60 * 60 * 1000);

    await PasswordReset.findOneAndUpdate(
      { email: user.email },
      { 
        token, 
        expiresAt,
        used: false
      },
      { 
        upsert: true, 
        new: true 
      }
    );

    const emailSent = await sendPasswordResetEmail(user.email, token);
    
    if (!emailSent) {
      console.warn('Password reset email failed to send for:', user.email);
    }

    res.json({ 
      success: true,
      message: 'Password reset email sent',
      emailSent: emailSent
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error processing password reset' 
    });
  }
};

exports.resetPassword = async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    
    if (!token || !newPassword) {
      return res.status(400).json({ 
        success: false,
        message: 'Token and new password are required' 
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ 
        success: false,
        message: 'Password must be at least 6 characters' 
      });
    }

    const resetRecord = await PasswordReset.findOne({ 
      token, 
      expiresAt: { $gt: new Date() },
      used: false
    });

    if (!resetRecord) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid or expired reset token' 
      });
    }

    const user = await User.findOne({ email: resetRecord.email });
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found' 
      });
    }

    user.password = newPassword;
    await user.save();

    resetRecord.used = true;
    resetRecord.usedAt = new Date();
    await resetRecord.save();

    res.json({ 
      success: true,
      message: 'Password reset successfully. You can now login with your new password.' 
    });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error resetting password' 
    });
  }
};

exports.verifyEmail = async (req, res) => {
  try {
    const { token } = req.params;
    
    const user = await User.findOne({
      emailVerificationToken: token,
      emailVerificationExpires: { $gt: new Date() }
    });

    if (!user) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid or expired verification token' 
      });
    }

    user.verified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpires = undefined;
    await user.save();

    res.json({ 
      success: true,
      message: 'Email verified successfully. You can now login to your account.' 
    });
  } catch (error) {
    console.error('Email verification error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error verifying email' 
    });
  }
};

exports.resendVerification = async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ 
        success: false,
        message: 'Email is required' 
      });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found' 
      });
    }

    if (user.verified) {
      return res.status(400).json({ 
        success: false,
        message: 'Email already verified' 
      });
    }

    const emailVerificationToken = crypto.randomBytes(32).toString('hex');
    const emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);

    user.emailVerificationToken = emailVerificationToken;
    user.emailVerificationExpires = emailVerificationExpires;
    await user.save();

    const emailSent = await sendVerificationEmail(user.email, emailVerificationToken);
    
    if (!emailSent) {
      console.warn('Resend verification email failed for:', user.email);
    }

    res.json({ 
      success: true,
      message: 'Verification email sent successfully',
      emailSent: emailSent
    });
  } catch (error) {
    console.error('Resend verification error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error sending verification email' 
    });
  }
};

exports.refreshToken = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(400).json({ 
        success: false,
        message: 'Refresh token required' 
      });
    }

    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found' 
      });
    }

    if (user.suspended) {
      return res.status(403).json({ 
        success: false,
        message: 'Account suspended' 
      });
    }

    const tokens = generateTokens(user._id);
    
    res.json({ 
      success: true,
      ...tokens 
    });
  } catch (error) {
    res.status(403).json({ 
      success: false,
      message: 'Invalid refresh token' 
    });
  }
};

exports.logout = async (req, res) => {
  try {
    res.json({ 
      success: true,
      message: 'Logged out successfully' 
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error during logout' 
    });
  }
};

exports.getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found' 
      });
    }
    
    res.json({ 
      success: true,
      user: { 
        id: user._id, 
        username: user.username, 
        email: user.email,
        role: user.role,
        balance: user.balance,
        investment: user.investment,
        verified: user.verified,
        profile: user.profile,
        referrals: user.referrals,
        tasksCompleted: user.tasksCompleted.length,
        totalEarned: user.totalEarned,
        totalWithdrawn: user.totalWithdrawn,
        totalReferrals: user.referrals.length,
        joinedAt: user.createdAt,
        lastLogin: user.lastLogin
      } 
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error retrieving profile' 
    });
  }
};

exports.updateProfile = async (req, res) => {
  try {
    const { fullName, phone, bankDetails } = req.body;
    const user = await User.findById(req.userId);
    
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found' 
      });
    }

    if (fullName) user.profile.fullName = fullName;
    if (phone) user.profile.phone = phone;
    if (bankDetails) {
      user.profile.bankDetails = {
        ...user.profile.bankDetails,
        ...bankDetails
      };
    }

    await user.save();
    
    res.json({ 
      success: true,
      message: 'Profile updated successfully',
      profile: user.profile 
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error updating profile' 
    });
  }
};

exports.changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.userId);
    
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found' 
      });
    }

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ 
        success: false,
        message: 'Current password and new password are required' 
      });
    }

    const isCurrentPasswordValid = await user.comparePassword(currentPassword);
    if (!isCurrentPasswordValid) {
      return res.status(400).json({ 
        success: false,
        message: 'Current password is incorrect' 
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ 
        success: false,
        message: 'New password must be at least 6 characters' 
      });
    }

    user.password = newPassword;
    await user.save();

    res.json({ 
      success: true,
      message: 'Password changed successfully' 
    });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error changing password' 
    });
  }
};

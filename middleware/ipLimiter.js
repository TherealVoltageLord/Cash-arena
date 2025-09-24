const User = require('../models/User');

exports.oneAccountPerIP = async (req, res, next) => {
  try {
    const existingUser = await User.findOne({ lastIP: req.ip });
    if (existingUser) {
      return res.status(400).json({ message: 'One account per IP address allowed' });
    }
    next();
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};
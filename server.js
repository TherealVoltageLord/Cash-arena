require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');
const rateLimit = require('express-rate-limit');

const connectDB = require('./config/db');

const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const transactionRoutes = require('./routes/transactionRoutes');
const taskRoutes = require('./routes/taskRoutes');
const rewardRoutes = require('./routes/rewardRoutes');
const adminRoutes = require('./routes/adminRoutes');
const announcementRoutes = require('./routes/announcementRoutes');

const app = express();

connectDB();

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: {
    error: 'Too many requests from this IP, please try again after 15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: {
    error: 'Too many authentication attempts, please try again after 15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false
});

app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.use(express.static('public'));

app.use('/api/auth', authLimiter, authRoutes);
app.use('/api/user', limiter, userRoutes);
app.use('/api/transaction', limiter, transactionRoutes);
app.use('/api/tasks', limiter, taskRoutes);
app.use('/api/rewards', limiter, rewardRoutes);
app.use('/api/admin', limiter, adminRoutes);
app.use('/api/announcements', limiter, announcementRoutes);

app.get('/api/health', function(req, res) {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development'
  });
});

app.get('/ref/:refCode', async function(req, res) {
  try {
    const refCode = req.params.refCode;
    const user = await mongoose.model('User').findOne({ referralCode: refCode });
    
    if (user) {
      res.redirect('/register?ref=' + refCode);
    } else {
      res.redirect('/register');
    }
  } catch (error) {
    res.redirect('/register');
  }
});

app.get('/', function(req, res) {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', function(req, res) {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', function(req, res) {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/dashboard', function(req, res) {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/deposit', function(req, res) {
  res.sendFile(path.join(__dirname, 'public', 'deposit.html'));
});

app.get('/withdraw', function(req, res) {
  res.sendFile(path.join(__dirname, 'public', 'withdraw.html'));
});

app.get('/tasks', function(req, res) {
  res.sendFile(path.join(__dirname, 'public', 'tasks.html'));
});

app.get('/referral', function(req, res) {
  res.sendFile(path.join(__dirname, 'public', 'referral.html'));
});

app.get('/admin', function(req, res) {
  res.sendFile(path.join(__dirname, 'public', 'admin-login.html'));
});

app.get('/admin/dashboard', function(req, res) {
  res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
});

app.get('/404', function(req, res) {
  res.sendFile(path.join(__dirname, 'public', '404.html'));
});

app.get('*', function(req, res) {
  res.redirect('/404');
});

app.use(function(error, req, res, next) {
  console.error('Global error handler:', error);
  
  if (error.name === 'ValidationError') {
    return res.status(400).json({
      success: false,
      message: 'Validation error',
      errors: Object.values(error.errors).map(function(err) { return err.message; })
    });
  }
  
  if (error.name === 'CastError') {
    return res.status(400).json({
      success: false,
      message: 'Invalid ID format'
    });
  }
  
  if (error.code === 11000) {
    const field = Object.keys(error.keyValue)[0];
    return res.status(400).json({
      success: false,
      message: field + ' already exists'
    });
  }
  
  if (error.name === 'JsonWebTokenError') {
    return res.status(401).json({
      success: false,
      message: 'Invalid token'
    });
  }
  
  if (error.name === 'TokenExpiredError') {
    return res.status(401).json({
      success: false,
      message: 'Token expired'
    });
  }

  res.status(error.status || 500).json({
    success: false,
    message: process.env.NODE_ENV === 'production' ? 'Internal server error' : error.message
  });
});

process.on('unhandledRejection', function(err) {
  console.error('Unhandled Promise Rejection:', err);
  process.exit(1);
});

process.on('uncaughtException', function(err) {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});

const PORT = process.env.PORT || 5000;

const server = app.listen(PORT, '0.0.0.0', function() {
  console.log('Server running on port ' + PORT);
  console.log('Environment: ' + (process.env.NODE_ENV || 'development'));
  console.log('MongoDB: ' + (mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'));
});

const gracefulShutdown = function(signal) {
  console.log(signal + ' received, shutting down gracefully...');
  
  server.close(function() {
    console.log('HTTP server closed');
    
    mongoose.connection.close(false, function() {
      console.log('MongoDB connection closed');
      process.exit(0);
    });
  });

  setTimeout(function() {
    console.error('Forced shutdown after timeout');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', function() {
  gracefulShutdown('SIGTERM');
});

process.on('SIGINT', function() {
  gracefulShutdown('SIGINT');
});

module.exports = app;

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
  res.sendFile(path.join(__dirname, 'public', 'adlog.html'));
});

app.get('/admin/dashboard', function(req, res) {
  res.sendFile(path.join(__dirname, 'public', 'ad-dash.html'));
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

// NOTE: This handler now attempts graceful shutdown instead of force-exiting immediately.
process.on('unhandledRejection', function(err) {
  console.error('Unhandled Promise Rejection:', err);
  // attempt graceful shutdown, label signal
  gracefulShutdown('unhandledRejection').catch((shutdownErr) => {
    console.error('Error during graceful shutdown after unhandledRejection:', shutdownErr);
    process.exit(1);
  });
});

// NOTE: This handler now attempts graceful shutdown too.
process.on('uncaughtException', function(err) {
  console.error('Uncaught Exception:', err);
  // attempt graceful shutdown, label signal
  gracefulShutdown('uncaughtException').catch((shutdownErr) => {
    console.error('Error during graceful shutdown after uncaughtException:', shutdownErr);
    process.exit(1);
  });
});

const PORT = process.env.PORT || 5000;

const server = app.listen(PORT, '0.0.0.0', function() {
  console.log('Server running on port ' + PORT);
  console.log('Environment: ' + (process.env.NODE_ENV || 'development'));
  console.log('MongoDB: ' + (mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'));
});

// Graceful shutdown using promises (compatible with Mongoose v7+)
const gracefulShutdown = async function(signal) {
  console.log(signal + ' received, shutting down gracefully...');

  // create a forced timeout in case shutdown hangs
  const forceTimeout = setTimeout(() => {
    console.error('Forced shutdown after timeout');
    process.exit(1);
  }, 10000);

  // helper to close server (wrapped in a Promise so we can await it)
  const closeServer = () => {
    return new Promise((resolve, reject) => {
      if (!server) {
        return resolve();
      }
      server.close((err) => {
        if (err) return reject(err);
        resolve();
      });
    });
  };

  try {
    await closeServer();
    console.log('HTTP server closed');
  } catch (err) {
    console.error('Error closing HTTP server:', err);
  }

  try {
    await mongoose.connection.close(false);
    console.log('MongoDB connection closed');
  } catch (err) {
    console.error('Error closing MongoDB connection:', err);
  } finally {
    clearTimeout(forceTimeout);
    process.exit(0);
  }
};

process.on('SIGTERM', function() {
  gracefulShutdown('SIGTERM').catch((err) => {
    console.error('Error during SIGTERM graceful shutdown:', err);
    process.exit(1);
  });
});

process.on('SIGINT', function() {
  gracefulShutdown('SIGINT').catch((err) => {
    console.error('Error during SIGINT graceful shutdown:', err);
    process.exit(1);
  });
});

module.exports = app;

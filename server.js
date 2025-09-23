const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');
const cors = require('cors');
const speakeasy = require('speakeasy');

const app = express();
const PORT = process.env.PORT || 3000;

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'public/uploads/')
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname)
  }
});
const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'), false);
    }
  }
});

app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));

app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static('public'));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many authentication attempts, please try again later.',
  skipSuccessfulRequests: true
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests, please try again later.'
});

app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);
app.use('/api/', apiLimiter);

// Database connection with better error handling
mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://casharena-admin:Voltage6@voltunix-cluster.ivkjo5a.mongodb.net/?retryWrites=true&w=majority&appName=voltunix-cluster', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 30000, // 30 seconds
  socketTimeoutMS: 45000, // 45 seconds
  maxPoolSize: 10,
  retryWrites: true,
  w: 'majority'
});

const db = mongoose.connection;

// Handle connection events with better error handling
db.on('error', (error) => {
  console.error('MongoDB connection error:', error);
});

db.on('connected', () => {
  console.log('Connected to MongoDB successfully');
});

db.on('disconnected', () => {
  console.log('MongoDB disconnected');
});

// Handle process termination
process.on('SIGINT', async () => {
  await mongoose.connection.close();
  process.exit(0);
});
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB successfully');
});

const UserSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: true, 
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 30,
    match: /^[a-zA-Z0-9_]+$/
  },
  email: { 
    type: String, 
    required: true, 
    unique: true,
    lowercase: true,
    match: /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/
  },
  password: { type: String, required: true },
  verified: { type: Boolean, default: false },
  balance: { type: Number, default: 0 },
  bonusBalance: { type: Number, default: 0 },
  investment: {
    amount: { type: Number, default: 0 },
    startDate: { type: Date },
    lastClaim: { type: Date },
    streak: { type: Number, default: 0 },
    tier: { type: String, enum: ['Bronze', 'Silver', 'Gold', 'Platinum'], default: 'Bronze' }
  },
  referralCode: { type: String, unique: true },
  referredBy: { type: String },
  referrals: [{ 
    username: String,
    email: String,
    joinedAt: Date,
    depositAmount: Number
  }],
  tasksCompleted: [{ 
    taskId: { type: mongoose.Schema.Types.ObjectId, ref: 'Task' },
    completedAt: { type: Date },
    expiresAt: { type: Date }
  }],
  lastIP: { type: String },
  devices: [{
    deviceId: String,
    userAgent: String,
    ip: String,
    lastLogin: Date
  }],
  role: { type: String, enum: ['user', 'admin', 'superadmin'], default: 'user' },
  suspended: { type: Boolean, default: false },
  loginAttempts: { type: Number, default: 0 },
  lockUntil: { type: Date },
  twoFactorEnabled: { type: Boolean, default: false },
  twoFactorSecret: { type: String },
  achievements: [{
    name: String,
    description: String,
    earnedAt: Date,
    reward: Number
  }],
  badges: [String],
  lastLoginBonus: { type: Date },
  totalLoginDays: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const ClaimSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  claimDate: { type: Date, default: Date.now },
  status: { type: String, enum: ['claimed', 'missed'], default: 'claimed' },
  type: { type: String, enum: ['investment', 'login_bonus'], default: 'investment' }
});

const TaskSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  image: { type: String },
  reward: { type: Number, required: true },
  type: { 
    type: String, 
    enum: ['daily', 'weekly', 'monthly', 'one-time', 'challenge'], 
    default: 'one-time' 
  },
  timeFrame: {
    startDate: { type: Date },
    endDate: { type: Date },
    duration: { type: Number },
    repeatable: { type: Boolean, default: false }
  },
  usersCompleted: [{ 
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    completedAt: { type: Date },
    expiresAt: { type: Date }
  }],
  active: { type: Boolean, default: true },
  maxCompletions: { type: Number, default: 1 },
  requiredLevel: { type: String, enum: ['Bronze', 'Silver', 'Gold', 'Platinum'], default: 'Bronze' },
  challengeGoal: { type: Number },
  challengeProgress: { type: Map, of: Number },
  createdAt: { type: Date, default: Date.now }
});

const TransactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal'], required: true },
  amount: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  adminNote: { type: String },
  processedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  processedAt: { type: Date },
  twoFactorVerified: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const AuditLogSchema = new mongoose.Schema({
  adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  action: { type: String, required: true },
  targetType: { type: String },
  targetId: { type: String },
  details: { type: Object },
  ipAddress: { type: String },
  userAgent: { type: String },
  createdAt: { type: Date, default: Date.now }
});

const NotificationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  message: { type: String, required: true },
  type: { type: String, enum: ['info', 'success', 'warning', 'error'], default: 'info' },
  read: { type: Boolean, default: false },
  relatedId: { type: String },
  relatedType: { type: String },
  createdAt: { type: Date, default: Date.now }
});

const PasswordResetSchema = new mongoose.Schema({
  email: { type: String, required: true },
  token: { type: String, required: true },
  expiresAt: { type: Date, required: true },
  used: { type: Boolean, default: false }
});

const BlacklistedTokenSchema = new mongoose.Schema({
  token: { type: String, required: true, unique: true },
  expiresAt: { type: Date, required: true }
});

const AchievementSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  description: { type: String, required: true },
  criteria: { 
    type: { type: String, required: true },
    value: { type: Number, required: true }
  },
  reward: { type: Number, default: 0 },
  badge: { type: String },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Claim = mongoose.model('Claim', ClaimSchema);
const Task = mongoose.model('Task', TaskSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const AuditLog = mongoose.model('AuditLog', AuditLogSchema);
const Notification = mongoose.model('Notification', NotificationSchema);
const PasswordReset = mongoose.model('PasswordReset', PasswordResetSchema);
const BlacklistedToken = mongoose.model('BlacklistedToken', BlacklistedTokenSchema);
const Achievement = mongoose.model('Achievement', AchievementSchema);

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

const JWT_SECRET = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET;

function generateReferralCode() {
  return crypto.randomBytes(4).toString('hex').toUpperCase();
}

function generateDeviceId(req) {
  return crypto.createHash('md5').update(req.headers['user-agent'] + req.ip).digest('hex');
}

function calculateROI(amount) {
  if (amount >= 5000 && amount <= 20000) return 0.005;
  if (amount <= 50000) return 0.015;
  if (amount <= 100000) return 0.025;
  return 0.03;
}

function determineTier(amount) {
  if (amount >= 5000 && amount <= 20000) return 'Bronze';
  if (amount <= 50000) return 'Silver';
  if (amount <= 100000) return 'Gold';
  return 'Platinum';
}

async function createNotification(userId, title, message, type = 'info', relatedId = null, relatedType = null) {
  try {
    const notification = new Notification({
      userId,
      title,
      message,
      type,
      relatedId,
      relatedType
    });
    await notification.save();
  } catch (error) {
    console.error('Failed to create notification:', error);
  }
}

async function initializeAchievements() {
  const achievements = [
    {
      name: 'First Steps',
      description: 'Make your first deposit',
      criteria: { type: 'total_deposit', value: 5000 },
      reward: 500,
      badge: '🥇'
    },
    {
      name: 'Weekly Warrior',
      description: 'Maintain a 7-day claim streak',
      criteria: { type: 'streak', value: 7 },
      reward: 1000,
      badge: '🔥'
    },
    {
      name: 'Monthly Master',
      description: 'Maintain a 30-day claim streak',
      criteria: { type: 'streak', value: 30 },
      reward: 5000,
      badge: '👑'
    },
    {
      name: 'Social Butterfly',
      description: 'Refer 5 friends',
      criteria: { type: 'referrals', value: 5 },
      reward: 2500,
      badge: '🦋'
    },
    {
      name: 'Task Master',
      description: 'Complete 50 tasks',
      criteria: { type: 'tasks_completed', value: 50 },
      reward: 3000,
      badge: '✅'
    },
    {
      name: 'Dedicated Investor',
      description: 'Login for 100 days',
      criteria: { type: 'login_days', value: 100 },
      reward: 10000,
      badge: '💎'
    }
  ];

  for (const achievement of achievements) {
    await Achievement.findOneAndUpdate(
      { name: achievement.name },
      achievement,
      { upsert: true }
    );
  }
}

async function checkAndAwardAchievements(user, action, value) {
  try {
    const achievements = await Achievement.find({});
    
    for (const achievement of achievements) {
      const hasAchievement = user.achievements.some(a => a.name === achievement.name);
      
      if (!hasAchievement) {
        let awarded = false;
        
        switch (achievement.criteria.type) {
          case 'streak':
            if (user.investment.streak >= achievement.criteria.value) {
              awarded = true;
            }
            break;
          case 'referrals':
            if (user.referrals.length >= achievement.criteria.value) {
              awarded = true;
            }
            break;
          case 'total_deposit':
            if (user.investment.amount >= achievement.criteria.value) {
              awarded = true;
            }
            break;
          case 'login_days':
            if (user.totalLoginDays >= achievement.criteria.value) {
              awarded = true;
            }
            break;
          case 'tasks_completed':
            if (user.tasksCompleted.length >= achievement.criteria.value) {
              awarded = true;
            }
            break;
        }
        
        if (awarded) {
          user.achievements.push({
            name: achievement.name,
            description: achievement.description,
            earnedAt: new Date(),
            reward: achievement.reward
          });
          
          if (achievement.badge) {
            user.badges.push(achievement.badge);
          }
          
          user.balance += achievement.reward;
          
          await createNotification(
            user._id, 
            'Achievement Unlocked!', 
            `You earned the "${achievement.name}" achievement and received ₦${achievement.reward} bonus!`,
            'success'
          );
        }
      }
    }
    
    await user.save();
  } catch (error) {
    console.error('Error checking achievements:', error);
  }
}

async function logAdminAction(adminId, action, targetType, targetId, details, req) {
  try {
    const auditLog = new AuditLog({
      adminId,
      action,
      targetType,
      targetId,
      details,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    });
    await auditLog.save();
  } catch (error) {
    console.error('Failed to log admin action:', error);
  }
}

async function isAccountLocked(email) {
  const user = await User.findOne({ email });
  if (user && user.lockUntil && user.lockUntil > Date.now()) {
    return true;
  }
  return false;
}

async function failedLoginAttempt(email) {
  const user = await User.findOne({ email });
  if (user) {
    const updates = {
      $inc: { loginAttempts: 1 },
      $set: { lockUntil: null }
    };
    
    if (user.loginAttempts + 1 >= 5) {
      updates.$set.lockUntil = Date.now() + 30 * 60 * 1000;
    }
    
    await User.updateOne({ email }, updates);
  }
}

async function successfulLogin(email) {
  await User.updateOne({ email }, {
    $set: { loginAttempts: 0, lockUntil: null }
  });
}

const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    const isBlacklisted = await BlacklistedToken.findOne({ token });
    if (isBlacklisted) {
      return res.status(403).json({ error: 'Token revoked. Please login again.' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        return res.status(403).json({ error: 'Invalid or expired token' });
      }
      req.user = user;
      next();
    });
  } catch (error) {
    res.status(500).json({ error: 'Authentication error' });
  }
};

const requireAdmin = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user || !['admin', 'superadmin'].includes(user.role)) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    req.adminUser = user;
    next();
  } catch (error) {
    res.status(500).json({ error: 'Authorization error' });
  }
};

const requireSuperAdmin = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user || user.role !== 'superadmin') {
      return res.status(403).json({ error: 'Super admin access required' });
    }
    next();
  } catch (error) {
    res.status(500).json({ error: 'Authorization error' });
  }
};

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/ref/:refCode', async (req, res) => {
  try {
    const referrer = await User.findOne({ referralCode: req.params.refCode });
    if (!referrer) {
      return res.redirect('/register?error=Invalid referral code');
    }
    res.redirect(`/register?ref=${req.params.refCode}`);
  } catch (error) {
    res.redirect('/register');
  }
});

app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, referredBy } = req.body;
    
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    const existingUser = await User.findOne({ 
      $or: [{ email: email.toLowerCase() }, { username }] 
    });
    
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }
    
    const ip = req.ip;
    const existingIP = await User.findOne({ lastIP: ip });
    if (existingIP) {
      return res.status(400).json({ error: 'Only one account per IP allowed' });
    }
    
    let validReferrer = null;
    if (referredBy) {
      validReferrer = await User.findOne({ referralCode: referredBy });
      if (!validReferrer) {
        return res.status(400).json({ error: 'Invalid referral code' });
      }
      
      const existingReferral = await User.findOne({ 
        lastIP: ip, 
        referredBy: referredBy 
      });
      if (existingReferral) {
        return res.status(400).json({ error: 'This referral code has already been used from your IP' });
      }
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const referralCode = generateReferralCode();
    
    const user = new User({
      username,
      email: email.toLowerCase(),
      password: hashedPassword,
      referralCode,
      referredBy: validReferrer ? referredBy : null,
      lastIP: ip
    });
    
    await user.save();
    
    const verificationToken = jwt.sign({ email: email.toLowerCase() }, JWT_SECRET, { expiresIn: '24h' });
    const verificationUrl = `${req.protocol}://${req.get('host')}/api/verify/${verificationToken}`;
    
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Verify your Cash Arena account',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #3498db;">Welcome to Cash Arena!</h2>
          <p>Please verify your email address to activate your account:</p>
          <a href="${verificationUrl}" style="background-color: #3498db; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">
            Verify Email Address
          </a>
          <p>This link will expire in 24 hours.</p>
        </div>
      `
    });
    
    res.status(201).json({ 
      message: 'Account created successfully. Please check your email to verify your account.',
      referralCode: user.referralCode
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/resend-verification', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
    
    const user = await User.findOne({ email: email.toLowerCase() });
    
    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }
    
    if (user.verified) {
      return res.status(400).json({ error: 'Email already verified' });
    }
    
    const verificationToken = jwt.sign({ email: email.toLowerCase() }, JWT_SECRET, { expiresIn: '24h' });
    const verificationUrl = `${req.protocol}://${req.get('host')}/api/verify/${verificationToken}`;
    
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Verify your Cash Arena account',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #3498db;">Verify Your Email</h2>
          <p>Click the button below to verify your email address:</p>
          <a href="${verificationUrl}" style="background-color: #3498db; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">
            Verify Email Address
          </a>
          <p>This link will expire in 24 hours.</p>
        </div>
      `
    });
    
    res.json({ message: 'Verification email sent successfully' });
  } catch (error) {
    console.error('Resend verification error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/verify/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findOne({ email: decoded.email.toLowerCase() });
    
    if (!user) {
      return res.status(400).json({ error: 'Invalid verification token' });
    }
    
    if (user.verified) {
      return res.redirect('/login?message=already_verified');
    }
    
    user.verified = true;
    await user.save();
    
    await createNotification(
      user._id,
      'Welcome to Cash Arena!',
      'Your account has been verified successfully. Start your investment journey today!',
      'success'
    );
    
    res.redirect('/login?verified=true');
  } catch (error) {
    res.status(400).json({ error: 'Invalid or expired verification token' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password, twoFactorCode } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    
    if (await isAccountLocked(email.toLowerCase())) {
      return res.status(423).json({ error: 'Account temporarily locked. Try again in 30 minutes.' });
    }
    
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      await failedLoginAttempt(email.toLowerCase());
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    if (user.suspended) {
      return res.status(403).json({ error: 'Account suspended. Contact support.' });
    }
    
    if (!user.verified) {
      return res.status(400).json({ error: 'Please verify your email first' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      await failedLoginAttempt(email.toLowerCase());
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    if (user.twoFactorEnabled) {
      if (!twoFactorCode) {
        return res.status(400).json({ error: '2FA code required' });
      }
      
      const verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: twoFactorCode,
        window: 1
      });
      
      if (!verified) {
        await failedLoginAttempt(email.toLowerCase());
        return res.status(400).json({ error: 'Invalid 2FA code' });
      }
    }
    
    await successfulLogin(email.toLowerCase());
    
    const deviceId = generateDeviceId(req);
    const deviceIndex = user.devices.findIndex(d => d.deviceId === deviceId);
    
    if (deviceIndex === -1) {
      user.devices.push({
        deviceId,
        userAgent: req.headers['user-agent'],
        ip: req.ip,
        lastLogin: new Date()
      });
      
      await createNotification(
        user._id,
        'New Device Login',
        `A new device logged into your account from ${req.ip}. If this wasn't you, please contact support.`,
        'warning'
      );
    } else {
      user.devices[deviceIndex].lastLogin = new Date();
      user.devices[deviceIndex].ip = req.ip;
    }
    
    user.lastIP = req.ip;
    await user.save();
    
    const token = jwt.sign({ 
      id: user._id, 
      email: user.email,
      role: user.role 
    }, JWT_SECRET, { expiresIn: '15m' });
    
    const refreshToken = jwt.sign({ id: user._id }, REFRESH_SECRET, { expiresIn: '7d' });
    
    res.json({ 
      token, 
      refreshToken,
      user: { 
        id: user._id, 
        username: user.username, 
        email: user.email, 
        role: user.role,
        twoFactorEnabled: user.twoFactorEnabled,
        balance: user.balance,
        investment: user.investment
      } 
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/refresh-token', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(401).json({ error: 'Refresh token required' });
    }
    
    const decoded = jwt.verify(refreshToken, REFRESH_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(403).json({ error: 'Invalid refresh token' });
    }
    
    const newToken = jwt.sign({ 
      id: user._id, 
      email: user.email,
      role: user.role 
    }, JWT_SECRET, { expiresIn: '15m' });
    
    res.json({ token: newToken });
  } catch (error) {
    res.status(403).json({ error: 'Invalid refresh token' });
  }
});

app.post('/api/logout', authenticateToken, async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (token) {
      const blacklistedToken = new BlacklistedToken({
        token,
        expiresAt: new Date(Date.now() + 15 * 60 * 1000)
      });
      
      await blacklistedToken.save();
    }
    
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
    
    const user = await User.findOne({ email: email.toLowerCase() });
    
    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }
    
    const resetToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 1 * 60 * 60 * 1000);
    
    await PasswordReset.findOneAndUpdate(
      { email: email.toLowerCase() },
      { token: resetToken, expiresAt, used: false },
      { upsert: true, new: true }
    );
    
    const resetUrl = `${req.protocol}://${req.get('host')}/reset-password?token=${resetToken}`;
    
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Reset Your Cash Arena Password',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #3498db;">Password Reset Request</h2>
          <p>Click the button below to reset your password:</p>
          <a href="${resetUrl}" style="background-color: #e74c3c; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">
            Reset Password
          </a>
          <p>This link will expire in 1 hour.</p>
          <p>If you didn't request this, please ignore this email.</p>
        </div>
      `
    });
    
    res.json({ message: 'Password reset email sent' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    
    if (!token || !newPassword) {
      return res.status(400).json({ error: 'Token and new password are required' });
    }
    
    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    const resetRecord = await PasswordReset.findOne({ token, used: false });
    if (!resetRecord || resetRecord.expiresAt < new Date()) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }
    
    const user = await User.findOne({ email: resetRecord.email });
    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }
    
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();
    
    resetRecord.used = true;
    await resetRecord.save();
    
    await createNotification(
      user._id,
      'Password Updated',
      'Your password has been reset successfully.',
      'success'
    );
    
    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/claim-login-bonus', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    if (user.lastLoginBonus) {
      const lastBonusDate = new Date(user.lastLoginBonus);
      lastBonusDate.setHours(0, 0, 0, 0);
      
      if (lastBonusDate.getTime() === today.getTime()) {
        return res.status(400).json({ error: 'Login bonus already claimed today' });
      }
    }
    
    const loginBonus = parseInt(process.env.DAILY_LOGIN_BONUS) || 100;
    user.bonusBalance += loginBonus;
    user.lastLoginBonus = new Date();
    user.totalLoginDays += 1;
    
    const claim = new Claim({
      userId: user._id,
      amount: loginBonus,
      type: 'login_bonus'
    });
    
    await Promise.all([user.save(), claim.save()]);
    
    await createNotification(
      user._id,
      'Daily Login Bonus!',
      `You received ₦${loginBonus} bonus for logging in today!`,
      'success'
    );
    
    await checkAndAwardAchievements(user, 'login_days', user.totalLoginDays);
    
    res.json({ 
      message: 'Login bonus claimed successfully!', 
      bonus: loginBonus,
      totalLoginDays: user.totalLoginDays 
    });
  } catch (error) {
    console.error('Login bonus error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/dashboard', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
      .populate('tasksCompleted.taskId')
      .select('-password -twoFactorSecret');
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const today = new Date();
    const lastClaimDate = user.investment.lastClaim ? new Date(user.investment.lastClaim) : null;
    const canClaimToday = !lastClaimDate || 
      lastClaimDate.getDate() !== today.getDate() || 
      lastClaimDate.getMonth() !== today.getMonth() || 
      lastClaimDate.getFullYear() !== today.getFullYear();
    
    const lastLoginBonusDate = user.lastLoginBonus ? new Date(user.lastLoginBonus) : null;
    const canClaimLoginBonus = !lastLoginBonusDate || 
      lastLoginBonusDate.getDate() !== today.getDate() || 
      lastLoginBonusDate.getMonth() !== today.getMonth() || 
      lastLoginBonusDate.getFullYear() !== today.getFullYear();
    
    const dailyReward = user.investment.amount > 0 ? user.investment.amount * calculateROI(user.investment.amount) : 0;
    
    const pendingTransactions = await Transaction.find({
      userId: user._id,
      status: 'pending'
    }).sort({ createdAt: -1 }).limit(5);
    
    const recentClaims = await Claim.find({
      userId: user._id
    }).sort({ claimDate: -1 }).limit(10);
    
    const notifications = await Notification.find({
      userId: user._id,
      read: false
    }).sort({ createdAt: -1 }).limit(10);
    
    res.json({
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        balance: user.balance,
        bonusBalance: user.bonusBalance,
        investment: user.investment,
        referralCode: user.referralCode,
        referrals: user.referrals,
        achievements: user.achievements,
        badges: user.badges,
        totalLoginDays: user.totalLoginDays,
        role: user.role,
        twoFactorEnabled: user.twoFactorEnabled
      },
      dailyReward,
      canClaimToday,
      canClaimLoginBonus,
      pendingTransactions,
      recentClaims,
      notifications
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/deposit', authenticateToken, async (req, res) => {
  try {
    const { amount } = req.body;
    
    const minDeposit = parseInt(process.env.MIN_DEPOSIT) || 5000;
    const maxDeposit = parseInt(process.env.MAX_DEPOSIT) || 100000;
    
    if (!amount || amount < minDeposit || amount > maxDeposit) {
      return res.status(400).json({ 
        error: `Deposit amount must be between ₦${minDeposit.toLocaleString()} and ₦${maxDeposit.toLocaleString()}` 
      });
    }
    
    const user = await User.findById(req.user.id);
    if (user.suspended) {
      return res.status(403).json({ error: 'Account suspended. Cannot deposit.' });
    }
    
    const transaction = new Transaction({
      userId: user._id,
      type: 'deposit',
      amount,
      status: 'pending'
    });
    
    await transaction.save();
    
    await createNotification(
      user._id,
      'Deposit Request Submitted',
      `Your deposit of ₦${amount.toLocaleString()} is pending admin approval.`,
      'info',
      transaction._id.toString(),
      'transaction'
    );
    
    res.json({ 
      message: 'Deposit request submitted. Waiting for admin approval.',
      transactionId: transaction._id 
    });
  } catch (error) {
    console.error('Deposit error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/withdraw', authenticateToken, async (req, res) => {
  try {
    const { amount, twoFactorCode } = req.body;
    
    const minWithdrawal = parseInt(process.env.MIN_WITHDRAWAL) || 10000;
    
    if (!amount || amount < minWithdrawal) {
      return res.status(400).json({ 
        error: `Minimum withdrawal is ₦${minWithdrawal.toLocaleString()}` 
      });
    }
    
    const user = await User.findById(req.user.id);
    if (user.suspended) {
      return res.status(403).json({ error: 'Account suspended. Cannot withdraw.' });
    }
    
    const availableBalance = user.balance;
    if (availableBalance < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    if (user.twoFactorEnabled && !twoFactorCode) {
      return res.status(400).json({ error: '2FA code required for withdrawal' });
    }
    
    if (user.twoFactorEnabled) {
      const verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: twoFactorCode,
        window: 1
      });
      
      if (!verified) {
        return res.status(400).json({ error: 'Invalid 2FA code' });
      }
    }
    
    const lastWithdrawal = await Transaction.findOne({
      userId: user._id,
      type: 'withdrawal',
      status: 'approved'
    }).sort({ createdAt: -1 });
    
    if (lastWithdrawal) {
      const oneWeekAgo = new Date();
      oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);
      
      if (lastWithdrawal.createdAt > oneWeekAgo) {
        return res.status(400).json({ error: 'You can only withdraw once per week' });
      }
    }
    
    const transaction = new Transaction({
      userId: user._id,
      type: 'withdrawal',
      amount,
      status: 'pending',
      twoFactorVerified: user.twoFactorEnabled
    });
    
    await transaction.save();
    
    await createNotification(
      user._id,
      'Withdrawal Request Submitted',
      `Your withdrawal of ₦${amount.toLocaleString()} is pending admin approval.`,
      'info',
      transaction._id.toString(),
      'transaction'
    );
    
    res.json({ 
      message: 'Withdrawal request submitted. Waiting for admin approval.',
      transactionId: transaction._id 
    });
  } catch (error) {
    console.error('Withdrawal error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/claim', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    if (user.investment.amount === 0) {
      return res.status(400).json({ error: 'You need to make a deposit first' });
    }
    
    const today = new Date();
    const lastClaimDate = user.investment.lastClaim ? new Date(user.investment.lastClaim) : null;
    
    if (lastClaimDate && 
        lastClaimDate.getDate() === today.getDate() && 
        lastClaimDate.getMonth() === today.getMonth() && 
        lastClaimDate.getFullYear() === today.getFullYear()) {
      return res.status(400).json({ error: 'You have already claimed your daily reward today' });
    }
    
    if (lastClaimDate) {
      const daysSinceLastClaim = Math.floor((today - lastClaimDate) / (1000 * 60 * 60 * 24));
      if (daysSinceLastClaim > 1) {
        user.investment.streak = 0;
      } else if (daysSinceLastClaim === 1) {
        user.investment.streak += 1;
      }
    } else {
      user.investment.streak = 1;
    }
    
    const roiRate = calculateROI(user.investment.amount);
    const dailyReward = user.investment.amount * roiRate;
    
    let streakBonus = 0;
    const streakBonusAmount = parseInt(process.env.STREAK_BONUS) || 2000;
    if (user.investment.streak > 0 && user.investment.streak % 7 === 0) {
      streakBonus = streakBonusAmount;
    }
    
    const totalReward = dailyReward + streakBonus;
    
    user.balance += totalReward;
    user.investment.lastClaim = today;
    
    const claim = new Claim({
      userId: user._id,
      amount: totalReward,
      status: 'claimed'
    });
    
    await Promise.all([user.save(), claim.save()]);
    
    await createNotification(
      user._id,
      'Daily Reward Claimed!',
      `You claimed ₦${totalReward.toFixed(2)} daily reward (Streak: ${user.investment.streak} days)`,
      'success'
    );
    
    await checkAndAwardAchievements(user, 'streak', user.investment.streak);
    
    res.json({ 
      message: `Daily reward claimed successfully!`, 
      reward: dailyReward,
      streakBonus,
      totalReward,
      streak: user.investment.streak
    });
  } catch (error) {
    console.error('Claim error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const tasks = await Task.find({ active: true });
    const now = new Date();
    
    const tasksWithCompletion = tasks.map(task => {
      const userCompletion = user.tasksCompleted.find(
        t => t.taskId.toString() === task._id.toString()
      );
      
      const isAvailable = (!task.timeFrame.startDate || now >= task.timeFrame.startDate) &&
                         (!task.timeFrame.endDate || now <= task.timeFrame.endDate);
      
      const canComplete = !userCompletion || 
                         (task.repeatable && userCompletion.expiresAt && userCompletion.expiresAt <= now);
      
      return {
        _id: task._id,
        name: task.name,
        description: task.description,
        image: task.image,
        reward: task.reward,
        type: task.type,
        timeFrame: task.timeFrame,
        active: task.active,
        maxCompletions: task.maxCompletions,
        requiredLevel: task.requiredLevel,
        completed: !!userCompletion,
        canComplete: isAvailable && canComplete,
        isAvailable,
        timeRemaining: task.timeFrame.endDate ? task.timeFrame.endDate - now : null
      };
    });
    
    res.json(tasksWithCompletion);
  } catch (error) {
    console.error('Tasks error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/tasks/:taskId/complete', authenticateToken, async (req, res) => {
  try {
    const { taskId } = req.params;
    const user = await User.findById(req.user.id);
    const task = await Task.findById(taskId);
    
    if (!task) {
      return res.status(404).json({ error: 'Task not found' });
    }
    
    if (!task.active) {
      return res.status(400).json({ error: 'Task is not active' });
    }
    
    const now = new Date();
    
    if (task.timeFrame.startDate && now < task.timeFrame.startDate) {
      return res.status(400).json({ error: 'Task is not yet available' });
    }
    
    if (task.timeFrame.endDate && now > task.timeFrame.endDate) {
      return res.status(400).json({ error: 'Task has expired' });
    }
    
    const tierOrder = { 'Bronze': 1, 'Silver': 2, 'Gold': 3, 'Platinum': 4 };
    if (tierOrder[user.investment.tier] < tierOrder[task.requiredLevel]) {
      return res.status(400).json({ 
        error: `This task requires ${task.requiredLevel} investment tier` 
      });
    }
    
    const existingCompletion = user.tasksCompleted.find(
      t => t.taskId.toString() === taskId
    );
    
    if (existingCompletion) {
      if (task.timeFrame.duration && task.repeatable) {
        if (existingCompletion.expiresAt > now) {
          return res.status(400).json({ error: 'You can complete this task again after the time frame expires' });
        }
        user.tasksCompleted = user.tasksCompleted.filter(
          t => t.taskId.toString() !== taskId
        );
      } else if (!task.repeatable) {
        return res.status(400).json({ error: 'Task already completed' });
      }
    }
    
    const userCompletions = user.tasksCompleted.filter(
      t => t.taskId.toString() === taskId
    ).length;
    
    if (userCompletions >= task.maxCompletions) {
      return res.status(400).json({ error: 'Maximum completions reached for this task' });
    }
    
    let expiresAt = null;
    if (task.timeFrame.duration) {
      expiresAt = new Date(now.getTime() + task.timeFrame.duration * 60 * 60 * 1000);
    }
    
    user.balance += task.reward;
    user.tasksCompleted.push({
      taskId: task._id,
      completedAt: now,
      expiresAt
    });
    
    task.usersCompleted.push({
      userId: user._id,
      completedAt: now,
      expiresAt
    });
    
    if (task.type === 'challenge') {
      if (!task.challengeProgress) {
        task.challengeProgress = new Map();
      }
      const progress = (task.challengeProgress.get(user._id.toString()) || 0) + 1;
      task.challengeProgress.set(user._id.toString(), progress);
    }
    
    await Promise.all([user.save(), task.save()]);
    
    await createNotification(
      user._id,
      'Task Completed!',
      `You completed "${task.name}" and earned ₦${task.reward}!`,
      'success',
      task._id.toString(),
      'task'
    );
    
    await checkAndAwardAchievements(user, 'tasks_completed', user.tasksCompleted.length);
    
    res.json({ 
      message: 'Task completed successfully', 
      reward: task.reward,
      expiresAt 
    });
  } catch (error) {
    console.error('Task completion error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/leaderboard', authenticateToken, async (req, res) => {
  try {
    const topInvestors = await User.find({ 
      'investment.amount': { $gt: 0 } 
    })
    .sort({ 'investment.amount': -1 })
    .limit(10)
    .select('username investment.amount investment.tier');
    
    const topReferrers = await User.aggregate([
      { $match: { referrals: { $exists: true, $ne: [] } } },
      { $project: { username: 1, referralCount: { $size: '$referrals' } } },
      { $sort: { referralCount: -1 } },
      { $limit: 10 }
    ]);
    
    const topClaimers = await User.find({ 
      'investment.streak': { $gt: 0 } 
    })
    .sort({ 'investment.streak': -1 })
    .limit(10)
    .select('username investment.streak');
    
    const topBalances = await User.find({ 
      balance: { $gt: 0 } 
    })
    .sort({ balance: -1 })
    .limit(10)
    .select('username balance');
    
    const topWithdrawals = await Transaction.aggregate([
      { $match: { type: 'withdrawal', status: 'approved' } },
      { $group: { _id: '$userId', totalWithdrawn: { $sum: '$amount' } } },
      { $sort: { totalWithdrawn: -1 } },
      { $limit: 10 },
      { $lookup: { from: 'users', localField: '_id', foreignField: '_id', as: 'user' } },
      { $unwind: '$user' },
      { $project: { username: '$user.username', totalWithdrawn: 1 } }
    ]);
    
    res.json({
      investors: topInvestors,
      referrers: topReferrers,
      claimers: topClaimers,
      balances: topBalances,
      withdrawals: topWithdrawals
    });
  } catch (error) {
    console.error('Leaderboard error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    
    const notifications = await Notification.find({ userId: req.user.id })
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);
    
    const total = await Notification.countDocuments({ userId: req.user.id });
    
    res.json({
      notifications,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page),
      total
    });
  } catch (error) {
    console.error('Notifications error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/notifications/:id/read', authenticateToken, async (req, res) => {
  try {
    const notification = await Notification.findOneAndUpdate(
      { _id: req.params.id, userId: req.user.id },
      { read: true },
      { new: true }
    );
    
    if (!notification) {
      return res.status(404).json({ error: 'Notification not found' });
    }
    
    res.json({ message: 'Notification marked as read', notification });
  } catch (error) {
    console.error('Notification read error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/2fa/setup', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    if (user.twoFactorEnabled) {
      return res.status(400).json({ error: '2FA is already enabled' });
    }
    
    const secret = speakeasy.generateSecret({
      name: `Cash Arena (${user.email})`
    });
    
    user.twoFactorSecret = secret.base32;
    await user.save();
    
    res.json({
      secret: secret.base32,
      qrCodeUrl: secret.otpauth_url
    });
  } catch (error) {
    console.error('2FA setup error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/2fa/verify', authenticateToken, async (req, res) => {
  try {
    const { token } = req.body;
    const user = await User.findById(req.user.id);
    
    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: token,
      window: 1
    });
    
    if (!verified) {
      return res.status(400).json({ error: 'Invalid verification code' });
    }
    
    user.twoFactorEnabled = true;
    await user.save();
    
    await createNotification(
      user._id,
      '2FA Enabled',
      'Two-factor authentication has been enabled for your account.',
      'success'
    );
    
    res.json({ message: '2FA enabled successfully' });
  } catch (error) {
    console.error('2FA verify error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/2fa/disable', authenticateToken, async (req, res) => {
  try {
    const { password, twoFactorCode } = req.body;
    const user = await User.findById(req.user.id);
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid password' });
    }
    
    if (user.twoFactorEnabled) {
      const verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: twoFactorCode,
        window: 1
      });
      
      if (!verified) {
        return res.status(400).json({ error: 'Invalid 2FA code' });
      }
    }
    
    user.twoFactorEnabled = false;
    user.twoFactorSecret = undefined;
    await user.save();
    
    await createNotification(
      user._id,
      '2FA Disabled',
      'Two-factor authentication has been disabled for your account.',
      'warning'
    );
    
    res.json({ message: '2FA disabled successfully' });
  } catch (error) {
    console.error('2FA disable error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/admin/dashboard', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const activeUsers = await User.countDocuments({ 'investment.amount': { $gt: 0 } });
    const suspendedUsers = await User.countDocuments({ suspended: true });
    
    const totalDeposits = await Transaction.aggregate([
      { $match: { type: 'deposit', status: 'approved' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    const totalWithdrawals = await Transaction.aggregate([
      { $match: { type: 'withdrawal', status: 'approved' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    const pendingDeposits = await Transaction.countDocuments({ 
      type: 'deposit', 
      status: 'pending' 
    });
    
    const pendingWithdrawals = await Transaction.countDocuments({ 
      type: 'withdrawal', 
      status: 'pending' 
    });
    
    const recentTransactions = await Transaction.find()
      .populate('userId', 'username email')
      .sort({ createdAt: -1 })
      .limit(10);
    
    const duplicateIPs = await User.aggregate([
      { $group: { _id: '$lastIP', count: { $sum: 1 } } },
      { $match: { count: { $gt: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);
    
    res.json({
      stats: {
        totalUsers,
        activeUsers,
        suspendedUsers,
        totalDeposits: totalDeposits[0]?.total || 0,
        totalWithdrawals: totalWithdrawals[0]?.total || 0,
        pendingDeposits,
        pendingWithdrawals
      },
      recentTransactions,
      potentialFraud: duplicateIPs
    });
  } catch (error) {
    console.error('Admin dashboard error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/admin/transactions', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { type, status, page = 1, limit = 20 } = req.query;
    
    const query = {};
    if (type) query.type = type;
    if (status) query.status = status;
    
    const transactions = await Transaction.find(query)
      .populate('userId', 'username email')
      .populate('processedBy', 'username')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);
    
    const total = await Transaction.countDocuments(query);
    
    res.json({
      transactions,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page),
      total
    });
  } catch (error) {
    console.error('Admin transactions error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/admin/transactions/:id/approve', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const transaction = await Transaction.findById(req.params.id).populate('userId');
    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }
    
    if (transaction.status !== 'pending') {
      return res.status(400).json({ error: 'Transaction already processed' });
    }
    
    if (transaction.type === 'deposit') {
      if (transaction.userId.investment.amount === 0) {
        transaction.userId.investment.amount = transaction.amount;
        transaction.userId.investment.startDate = new Date();
        transaction.userId.investment.tier = determineTier(transaction.amount);
        
        if (transaction.userId.referredBy) {
          const referrer = await User.findOne({ referralCode: transaction.userId.referredBy });
          if (referrer) {
            const referralBonus = parseInt(process.env.REFERRAL_BONUS) || 1000;
            referrer.balance += referralBonus;
            referrer.referrals.push({
              username: transaction.userId.username,
              email: transaction.userId.email,
              joinedAt: new Date(),
              depositAmount: transaction.amount
            });
            await referrer.save();
            
            await createNotification(
              referrer._id,
              'Referral Bonus!',
              `You received ₦${referralBonus} bonus for ${transaction.userId.username}'s deposit!`,
              'success'
            );
            
            await checkAndAwardAchievements(referrer, 'referrals', referrer.referrals.length);
          }
        }
      } else {
        transaction.userId.investment.amount += transaction.amount;
        transaction.userId.investment.tier = determineTier(transaction.userId.investment.amount);
      }
      
      await createNotification(
        transaction.userId._id,
        'Deposit Approved!',
        `Your deposit of ₦${transaction.amount.toLocaleString()} has been approved.`,
        'success',
        transaction._id.toString(),
        'transaction'
      );
    } else if (transaction.type === 'withdrawal') {
      if (transaction.userId.balance < transaction.amount) {
        return res.status(400).json({ error: 'User has insufficient balance' });
      }
      transaction.userId.balance -= transaction.amount;
      
      await createNotification(
        transaction.userId._id,
        'Withdrawal Approved!',
        `Your withdrawal of ₦${transaction.amount.toLocaleString()} has been approved. Funds will be transferred shortly.`,
        'success',
        transaction._id.toString(),
        'transaction'
      );
    }
    
    transaction.status = 'approved';
    transaction.processedBy = req.user.id;
    transaction.processedAt = new Date();
    transaction.adminNote = req.body.note;
    
    await Promise.all([transaction.save(), transaction.userId.save()]);
    
    await logAdminAction(
      req.user.id, 
      'APPROVE_TRANSACTION', 
      'transaction', 
      transaction._id.toString(), 
      { 
        type: transaction.type, 
        amount: transaction.amount,
        note: req.body.note 
      },
      req
    );
    
    res.json({ message: 'Transaction approved successfully' });
  } catch (error) {
    console.error('Approve transaction error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/admin/transactions/:id/reject', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const transaction = await Transaction.findById(req.params.id).populate('userId');
    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }
    
    if (transaction.status !== 'pending') {
      return res.status(400).json({ error: 'Transaction already processed' });
    }
    
    if (transaction.type === 'withdrawal') {
      transaction.userId.balance += transaction.amount;
    }
    
    transaction.status = 'rejected';
    transaction.processedBy = req.user.id;
    transaction.processedAt = new Date();
    transaction.adminNote = req.body.note;
    
    await Promise.all([transaction.save(), transaction.userId.save()]);
    
    await createNotification(
      transaction.userId._id,
      `Transaction ${transaction.type === 'deposit' ? 'Deposit' : 'Withdrawal'} Rejected`,
      `Your ${transaction.type} of ₦${transaction.amount.toLocaleString()} was rejected. Reason: ${req.body.note || 'Contact support for details.'}`,
      'error',
      transaction._id.toString(),
      'transaction'
    );
    
    await logAdminAction(
      req.user.id, 
      'REJECT_TRANSACTION', 
      'transaction', 
      transaction._id.toString(), 
      { 
        type: transaction.type, 
        amount: transaction.amount,
        note: req.body.note 
      },
      req
    );
    
    res.json({ message: 'Transaction rejected successfully' });
  } catch (error) {
    console.error('Reject transaction error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { search, page = 1, limit = 20, suspended } = req.query;
    
    const query = {};
    if (search) {
      query.$or = [
        { username: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }
    
    if (suspended !== undefined) {
      query.suspended = suspended === 'true';
    }
    
    const users = await User.find(query)
      .select('-password -twoFactorSecret')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);
    
    const total = await User.countDocuments(query);
    
    res.json({
      users,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page),
      total
    });
  } catch (error) {
    console.error('Admin users error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/admin/users/:id/suspend', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id, 
      { suspended: true }, 
      { new: true }
    ).select('-password -twoFactorSecret');
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    await createNotification(
      user._id,
      'Account Suspended',
      'Your account has been suspended. Please contact support for more information.',
      'error'
    );
    
    await logAdminAction(
      req.user.id, 
      'SUSPEND_USER', 
      'user', 
      req.params.id, 
      { username: user.username },
      req
    );
    
    res.json({ message: 'User suspended successfully', user });
  } catch (error) {
    console.error('Suspend user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/admin/users/:id/unsuspend', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id, 
      { suspended: false }, 
      { new: true }
    ).select('-password -twoFactorSecret');
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    await createNotification(
      user._id,
      'Account Reactivated',
      'Your account has been reactivated. You can now access all features.',
      'success'
    );
    
    await logAdminAction(
      req.user.id, 
      'UNSUSPEND_USER', 
      'user', 
      req.params.id, 
      { username: user.username },
      req
    );
    
    res.json({ message: 'User unsuspended successfully', user });
  } catch (error) {
    console.error('Unsuspend user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/admin/users/:id/reset-balance', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id, 
      { balance: 0, bonusBalance: 0 }, 
      { new: true }
    ).select('-password -twoFactorSecret');
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    await createNotification(
      user._id,
      'Balance Reset',
      'Your account balance has been reset by an administrator.',
      'warning'
    );
    
    await logAdminAction(
      req.user.id, 
      'RESET_BALANCE', 
      'user', 
      req.params.id, 
      { username: user.username },
      req
    );
    
    res.json({ message: 'User balance reset successfully', user });
  } catch (error) {
    console.error('Reset balance error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/admin/tasks', authenticateToken, requireAdmin, upload.single('image'), async (req, res) => {
  try {
    const { 
      name, 
      description, 
      reward, 
      type, 
      timeFrame,
      active,
      maxCompletions,
      requiredLevel,
      challengeGoal
    } = req.body;
    
    if (!name || !description || !reward) {
      return res.status(400).json({ error: 'Name, description, and reward are required' });
    }
    
    const image = req.file ? `/uploads/${req.file.filename}` : null;
    
    const taskData = {
      name,
      description,
      image,
      reward: parseFloat(reward),
      type: type || 'one-time',
      active: active !== undefined ? JSON.parse(active) : true,
      maxCompletions: parseInt(maxCompletions) || 1,
      requiredLevel: requiredLevel || 'Bronze'
    };
    
    if (timeFrame) {
      taskData.timeFrame = JSON.parse(timeFrame);
    }
    
    if (type === 'challenge' && challengeGoal) {
      taskData.challengeGoal = parseInt(challengeGoal);
      taskData.challengeProgress = new Map();
    }
    
    const task = new Task(taskData);
    await task.save();
    
    await logAdminAction(
      req.user.id, 
      'CREATE_TASK', 
      'task', 
      task._id.toString(), 
      { name, reward: task.reward, type: task.type },
      req
    );
    
    res.status(201).json({ message: 'Task created successfully', task });
  } catch (error) {
    console.error('Create task error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/admin/tasks/:id', authenticateToken, requireAdmin, upload.single('image'), async (req, res) => {
  try {
    const updates = { ...req.body };
    
    if (req.file) {
      updates.image = `/uploads/${req.file.filename}`;
    }
    
    if (updates.reward) {
      updates.reward = parseFloat(updates.reward);
    }
    
    if (updates.maxCompletions) {
      updates.maxCompletions = parseInt(updates.maxCompletions);
    }
    
    if (updates.active !== undefined) {
      updates.active = JSON.parse(updates.active);
    }
    
    const task = await Task.findByIdAndUpdate(req.params.id, updates, { new: true });
    
    if (!task) {
      return res.status(404).json({ error: 'Task not found' });
    }
    
    await logAdminAction(
      req.user.id, 
      'UPDATE_TASK', 
      'task', 
      req.params.id, 
      updates,
      req
    );
    
    res.json({ message: 'Task updated successfully', task });
  } catch (error) {
    console.error('Update task error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/admin/tasks/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const task = await Task.findByIdAndDelete(req.params.id);
    
    if (!task) {
      return res.status(404).json({ error: 'Task not found' });
    }
    
    await logAdminAction(
      req.user.id, 
      'DELETE_TASK', 
      'task', 
      req.params.id, 
      { name: task.name },
      req
    );
    
    res.json({ message: 'Task deleted successfully' });
  } catch (error) {
    console.error('Delete task error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/admin/logs', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 50 } = req.query;
    
    const logs = await AuditLog.find()
      .populate('adminId', 'username email')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);
    
    const total = await AuditLog.countDocuments();
    
    res.json({
      logs,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page),
      total
    });
  } catch (error) {
    console.error('Admin logs error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/admin/create', authenticateToken, requireSuperAdmin, async (req, res) => {
  try {
    const { username, email, password, role = 'admin' } = req.body;
    
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }
    
    const existingUser = await User.findOne({ 
      $or: [{ email: email.toLowerCase() }, { username }] 
    });
    
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const newAdmin = new User({
      username,
      email: email.toLowerCase(),
      password: hashedPassword,
      role,
      verified: true
    });
    
    await newAdmin.save();
    
    await logAdminAction(
      req.user.id, 
      'CREATE_ADMIN', 
      'user', 
      newAdmin._id.toString(), 
      { username, email, role },
      req
    );
    
    res.json({ 
      message: 'Admin created successfully', 
      admin: { username, email, role } 
    });
  } catch (error) {
    console.error('Create admin error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/init-superadmin', async (req, res) => {
  try {
    const { email, password, username } = req.body;
    
    if (!email || !password || !username) {
      return res.status(400).json({ error: 'Email, password, and username are required' });
    }
    
    const existingSuperAdmin = await User.findOne({ role: 'superadmin' });
    if (existingSuperAdmin) {
      return res.status(400).json({ error: 'Super admin already exists' });
    }
    
    const existingUser = await User.findOne({ 
      $or: [{ email: email.toLowerCase() }, { username }] 
    });
    
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const superAdmin = new User({
      username,
      email: email.toLowerCase(),
      password: hashedPassword,
      role: 'superadmin',
      verified: true
    });
    
    await superAdmin.save();
    
    await initializeAchievements();
    
    res.json({ message: 'Super admin created successfully and achievements initialized' });
  } catch (error) {
    console.error('Init superadmin error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large. Maximum size is 5MB.' });
    }
  }
  
  res.status(500).json({ 
    error: process.env.NODE_ENV === 'production' 
      ? 'Internal server error' 
      : err.message 
  });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

async function initializeServer() {
  try {
    // Wait for MongoDB connection to be established first
    await new Promise((resolve, reject) => {
      db.once('open', resolve);
      db.once('error', reject);
      
      // Timeout after 30 seconds
      setTimeout(() => reject(new Error('MongoDB connection timeout')), 30000);
    });

    console.log('MongoDB connection established, initializing server...');
    
    // Now initialize achievements and check for super admin
    try {
      const achievementsCount = await Achievement.countDocuments();
      if (achievementsCount === 0) {
        await initializeAchievements();
        console.log('Achievements initialized successfully');
      }
    } catch (error) {
      console.log('Achievements initialization skipped:', error.message);
    }

    const superAdminExists = await User.findOne({ role: 'superadmin' });
    if (!superAdminExists) {
      console.log('No super admin found. Create one by POSTing to /api/init-superadmin');
    }
    
    app.listen(PORT, () => {
      console.log(`Cash Arena server running on port ${PORT}`);
      console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    });
  } catch (error) {
    console.error('Server initialization failed:', error);
    
    // Even if initialization fails, start the server but log the error
    app.listen(PORT, () => {
      console.log(`Cash Arena server running on port ${PORT} (with initialization errors)`);
      console.log('Error:', error.message);
    });
  }
}
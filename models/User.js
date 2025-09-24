const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: true, 
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 30
  },
  email: { 
    type: String, 
    required: true, 
    unique: true,
    trim: true,
    lowercase: true
  },
  password: { 
    type: String, 
    required: true,
    minlength: 6
  },
  verified: { 
    type: Boolean, 
    default: false 
  },
  emailVerificationToken: String,
  emailVerificationExpires: Date,
  role: { 
    type: String, 
    enum: ['user', 'admin', 'superadmin'], 
    default: 'user' 
  },
  balance: { 
    type: Number, 
    default: 0 
  },
  investment: {
    amount: { 
      type: Number, 
      default: 0 
    },
    startDate: Date,
    lastClaim: Date,
    streak: { 
      type: Number, 
      default: 0 
    },
    tier: { 
      type: String, 
      enum: ['Bronze', 'Silver', 'Gold'], 
      default: 'Bronze' 
    }
  },
  referralCode: { 
    type: String, 
    unique: true 
  },
  referredBy: String,
  referrals: [{
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    username: String,
    joinedAt: Date
  }],
  tasksCompleted: [{
    taskId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Task'
    },
    completedAt: Date,
    expiresAt: Date,
    evidence: String
  }],
  lastIP: String,
  suspended: { 
    type: Boolean, 
    default: false 
  },
  suspensionReason: String,
  loginAttempts: { 
    type: Number, 
    default: 0 
  },
  lockUntil: Date,
  profile: {
    fullName: String,
    phone: String,
    bankDetails: {
      bankName: String,
      accountNumber: String,
      accountName: String
    },
    profilePicture: String
  },
  lastLogin: Date,
  totalEarned: {
    type: Number,
    default: 0
  },
  totalWithdrawn: {
    type: Number,
    default: 0
  }
}, { 
  timestamps: true 
});

userSchema.index({ email: 1 });
userSchema.index({ username: 1 });
userSchema.index({ referralCode: 1 });
userSchema.index({ lastIP: 1 });
userSchema.index({ 'investment.tier': 1 });
userSchema.index({ createdAt: -1 });

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const saltRounds = 12;
    this.password = await bcrypt.hash(this.password, saltRounds);
    next();
  } catch (error) {
    next(error);
  }
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  if (!candidatePassword) return false;
  return await bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.isLocked = function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
};

userSchema.methods.incrementLoginAttempts = function() {
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.resetLoginAttempts();
  }
  
  this.loginAttempts += 1;
  
  if (this.loginAttempts >= 5) {
    this.lockUntil = Date.now() + 30 * 60 * 1000;
  }
};

userSchema.methods.resetLoginAttempts = function() {
  this.loginAttempts = 0;
  this.lockUntil = undefined;
};

userSchema.methods.getDailyROI = function() {
  const rates = { 
    Bronze: parseFloat(process.env.BRONZE_ROI || 0.5), 
    Silver: parseFloat(process.env.SILVER_ROI || 1.5), 
    Gold: parseFloat(process.env.GOLD_ROI || 2.5) 
  };
  return (this.investment.amount * rates[this.investment.tier]) / 100;
};

userSchema.methods.updateTier = function() {
  const amount = this.investment.amount;
  if (amount >= 51000) {
    this.investment.tier = 'Gold';
  } else if (amount >= 21000) {
    this.investment.tier = 'Silver';
  } else if (amount >= 5000) {
    this.investment.tier = 'Bronze';
  }
};

userSchema.methods.canClaimDaily = function() {
  if (this.investment.amount === 0) return false;
  
  const today = new Date().toDateString();
  const lastClaim = this.investment.lastClaim?.toDateString();
  return lastClaim !== today;
};

userSchema.methods.getReferralUrl = function() {
  return `${process.env.FRONTEND_URL}/ref/${this.referralCode}`;
};

userSchema.virtual('isEligibleForWithdrawal').get(function() {
  return this.balance >= parseInt(process.env.MIN_WITHDRAWAL || 10000);
});

userSchema.virtual('totalReferrals').get(function() {
  return this.referrals.length;
});

userSchema.set('toJSON', {
  transform: function(doc, ret) {
    delete ret.password;
    delete ret.emailVerificationToken;
    delete ret.emailVerificationExpires;
    delete ret.lockUntil;
    delete ret.loginAttempts;
    return ret;
  },
  virtuals: true
});

module.exports = mongoose.model('User', userSchema);
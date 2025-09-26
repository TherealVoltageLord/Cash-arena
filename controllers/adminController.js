const Transaction = require('../models/Transaction');
const User = require('../models/User');
const Task = require('../models/Task');
const AuditLog = require('../models/AuditLog');

exports.getDashboard = async (req, res) => {
  try {
    const pendingDeposits = await Transaction.countDocuments({ type: 'deposit', status: 'pending' });
    const pendingWithdrawals = await Transaction.countDocuments({ type: 'withdrawal', status: 'pending' });
    const totalUsers = await User.countDocuments();
    const totalBalance = await User.aggregate([{ $group: { _id: null, total: { $sum: '$balance' } } }]);

    res.json({
      success: true,
      stats: {
        pendingDeposits,
        pendingWithdrawals,
        totalUsers,
        totalBalance: totalBalance[0]?.total || 0
      }
    });
  } catch (error) {
    console.error('Admin dashboard error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error retrieving admin dashboard'
    });
  }
};

exports.getTransactions = async (req, res) => {
  try {
    const { page = 1, limit = 10, status, type } = req.query;
    const query = {};
    
    if (status) query.status = status;
    if (type) query.type = type;

    const transactions = await Transaction.find(query)
      .populate('userId', 'username email')
      .populate('processedBy', 'username')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await Transaction.countDocuments(query);

    res.json({
      success: true,
      transactions,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    console.error('Get transactions error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error retrieving transactions'
    });
  }
};

exports.updateTransaction = async (req, res) => {
  try {
    const { status, adminNote } = req.body;
    const transaction = await Transaction.findById(req.params.id).populate('userId');

    if (!transaction) {
      return res.status(404).json({
        success: false,
        message: 'Transaction not found'
      });
    }

    if (transaction.status !== 'pending') {
      return res.status(400).json({
        success: false,
        message: 'Transaction already processed'
      });
    }

    transaction.status = status;
    transaction.processedBy = req.userId;
    transaction.processedAt = new Date();
    transaction.adminNote = adminNote;

    if (status === 'approved') {
      if (transaction.type === 'deposit') {
        transaction.userId.balance += transaction.amount;
        transaction.userId.investment.amount += transaction.amount;
        transaction.userId.updateTier();
        
        if (transaction.userId.referredBy) {
          const referrer = await User.findOne({ referralCode: transaction.userId.referredBy });
          if (referrer) {
            referrer.balance += parseInt(process.env.REFERRAL_BONUS);
            await referrer.save();
          }
        }
      }
      await transaction.userId.save();
    } else if (status === 'rejected' && transaction.type === 'withdrawal') {
      transaction.userId.balance += transaction.amount;
      await transaction.userId.save();
    }

    await transaction.save();

    await AuditLog.create({
      adminId: req.userId,
      action: `transaction_${status}`,
      targetType: 'Transaction',
      targetId: transaction._id,
      details: { amount: transaction.amount, type: transaction.type },
      ipAddress: req.ip
    });

    res.json({
      success: true,
      message: `Transaction ${status} successfully`
    });
  } catch (error) {
    console.error('Update transaction error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error updating transaction'
    });
  }
};

exports.getUsers = async (req, res) => {
  try {
    const { page = 1, limit = 10, search } = req.query;
    const query = {};
    
    if (search) {
      query.$or = [
        { username: new RegExp(search, 'i') },
        { email: new RegExp(search, 'i') }
      ];
    }

    const users = await User.find(query)
      .select('-password')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await User.countDocuments(query);

    res.json({
      success: true,
      users,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error retrieving users'
    });
  }
};

exports.suspendUser = async (req, res) => {
  try {
    const { reason } = req.body;
    const user = await User.findById(req.params.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    user.suspended = !user.suspended;
    user.suspensionReason = reason;

    await user.save();

    await AuditLog.create({
      adminId: req.userId,
      action: user.suspended ? 'suspend_user' : 'unsuspend_user',
      targetType: 'User',
      targetId: user._id,
      details: { reason, username: user.username },
      ipAddress: req.ip
    });

    res.json({
      success: true,
      message: `User ${user.suspended ? 'suspended' : 'unsuspended'} successfully`
    });
  } catch (error) {
    console.error('Suspend user error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error suspending user'
    });
  }
};

exports.createTask = async (req, res) => {
  try {
    const { name, description, reward, type, requiredLevel, maxCompletions } = req.body;

    const task = new Task({
      name,
      description,
      reward: parseInt(reward),
      type,
      requiredLevel,
      maxCompletions: maxCompletions ? parseInt(maxCompletions) : null,
      active: true
    });

    await task.save();

    await AuditLog.create({
      adminId: req.userId,
      action: 'create_task',
      targetType: 'Task',
      targetId: task._id,
      details: { name, reward, type },
      ipAddress: req.ip
    });

    res.json({
      success: true,
      message: 'Task created successfully',
      task
    });
  } catch (error) {
    console.error('Create task error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error creating task'
    });
  }
};

exports.getStats = async (req, res) => {
  try {
    const totalEarnings = await User.aggregate([{ $group: { _id: null, total: { $sum: '$totalEarned' } } }]);
    const totalWithdrawals = await User.aggregate([{ $group: { _id: null, total: { $sum: '$totalWithdrawn' } } }]);
    
    const tierStats = await User.aggregate([
      { $group: { _id: '$investment.tier', count: { $sum: 1 }, totalInvestment: { $sum: '$investment.amount' } } }
    ]);

    res.json({
      success: true,
      stats: {
        totalEarnings: totalEarnings[0]?.total || 0,
        totalWithdrawals: totalWithdrawals[0]?.total || 0,
        tierStats
      }
    });
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error retrieving stats'
    });
  }
};

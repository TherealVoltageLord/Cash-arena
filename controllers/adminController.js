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
      pendingDeposits,
      pendingWithdrawals,
      totalUsers,
      totalBalance: totalBalance[0]?.total || 0
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

exports.updateTransaction = async (req, res) => {
  try {
    const { status, adminNote } = req.body;
    const transaction = await Transaction.findById(req.params.id).populate('userId');

    if (!transaction) return res.status(404).json({ message: 'Transaction not found' });

    if (transaction.status !== 'pending') {
      return res.status(400).json({ message: 'Transaction already processed' });
    }

    transaction.status = status;
    transaction.processedBy = req.userId;
    transaction.processedAt = new Date();
    transaction.adminNote = adminNote;

    if (status === 'approved') {
      if (transaction.type === 'deposit') {
        transaction.userId.balance += transaction.amount;
        transaction.userId.investment.amount += transaction.amount;
        updateUserTier(transaction.userId);
        
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

    res.json({ message: `Transaction ${status} successfully` });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

function updateUserTier(user) {
  const amount = user.investment.amount;
  if (amount >=81000) user.investment.tier = 'Plantinium';
 else if (amount >= 51000) user.investment.tier = 'Gold';
  else if (amount >= 21000) user.investment.tier = 'Silver';
  else if (amount >= 5000) user.investment.tier = 'Bronze';
}
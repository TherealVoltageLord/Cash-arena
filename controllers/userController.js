const User = require('../models/User');
const Transaction = require('../models/Transaction');

exports.getDashboard = async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const today = new Date().toDateString();
    const canClaimToday = user.investment.lastClaim?.toDateString() !== today;
    
    const dailyReward = user.getDailyROI();
    
    const recentTransactions = await Transaction.find({ userId: req.userId })
      .sort({ createdAt: -1 })
      .limit(5);

    res.json({
      success: true,
      balance: user.balance,
      investment: user.investment,
      canClaimToday,
      dailyReward,
      referralUrl: user.getReferralUrl(),
      recentTransactions,
      totalReferrals: user.referrals.length,
      tasksCompleted: user.tasksCompleted.length
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error retrieving dashboard'
    });
  }
};

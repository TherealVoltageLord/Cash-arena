const User = require('../models/User');
const Transaction = require('../models/Transaction');

exports.getDashboard = async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    const today = new Date().toDateString();
    const canClaimToday = user.investment.lastClaim?.toDateString() !== today;
    
    const dailyReward = calculateDailyROI(user.investment.amount, user.investment.tier);
    
    res.json({
      balance: user.balance,
      investment: user.investment,
      canClaimToday,
      dailyReward,
      referralUrl: `${process.env.FRONTEND_URL}/ref/${user.referralCode}`
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

function calculateDailyROI(amount, tier) {
  const rates = { Bronze: 0.5, Silver: 1.5, Gold: 2.5 };
  return (amount * rates[tier]) / 100;
}
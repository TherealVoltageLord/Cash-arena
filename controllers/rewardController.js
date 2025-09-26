const User = require('../models/User');
const Claim = require('../models/Claim');

exports.claimDaily = async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    const today = new Date().toDateString();
    
    if (user.investment.lastClaim?.toDateString() === today) {
      return res.status(400).json({
        success: false,
        message: 'Already claimed today'
      });
    }

    if (user.investment.amount === 0) {
      return res.status(400).json({
        success: false,
        message: 'No active investment'
      });
    }

    const dailyReward = user.getDailyROI();
    const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000).toDateString();
    const streakBroken = user.investment.lastClaim?.toDateString() !== yesterday;

    user.balance += dailyReward;
    user.totalEarned += dailyReward;
    user.investment.streak = streakBroken ? 1 : user.investment.streak + 1;
    user.investment.lastClaim = new Date();

    const claim = new Claim({
      userId: user._id,
      amount: dailyReward,
      claimDate: new Date(),
      status: 'claimed'
    });

    await user.save();
    await claim.save();

    res.json({
      success: true,
      message: 'Daily reward claimed',
      reward: dailyReward,
      streak: user.investment.streak,
      newBalance: user.balance
    });
  } catch (error) {
    console.error('Claim daily error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error claiming daily reward'
    });
  }
};

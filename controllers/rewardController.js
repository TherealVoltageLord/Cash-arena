const User = require('../models/User');
const Claim = require('../models/Claim');

exports.claimDaily = async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    const today = new Date().toDateString();
    
    if (user.investment.lastClaim?.toDateString() === today) {
      return res.status(400).json({ message: 'Already claimed today' });
    }

    if (user.investment.amount === 0) {
      return res.status(400).json({ message: 'No active investment' });
    }

    const dailyReward = calculateDailyROI(user.investment.amount, user.investment.tier);
    const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000).toDateString();
    const streakBroken = user.investment.lastClaim?.toDateString() !== yesterday;

    user.balance += dailyReward;
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

    res.json({ message: 'Daily reward claimed', reward: dailyReward, streak: user.investment.streak });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

function calculateDailyROI(amount, tier) {
  const rates = { Bronze: 0.5, Silver: 1.5, Gold: 2.5 };
  return (amount * rates[tier]) / 100;
}
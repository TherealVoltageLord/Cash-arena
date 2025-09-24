const Transaction = require('../models/Transaction');
const User = require('../models/User');

exports.deposit = async (req, res) => {
  try {
    const { amount } = req.body;
    const minDeposit = parseInt(process.env.MIN_DEPOSIT);
    const maxDeposit = parseInt(process.env.MAX_DEPOSIT);

    if (amount < minDeposit || amount > maxDeposit) {
      return res.status(400).json({ message: `Amount must be between ₦${minDeposit} and ₦${maxDeposit}` });
    }

    const transaction = new Transaction({
      userId: req.userId,
      type: 'deposit',
      amount,
      status: 'pending'
    });

    await transaction.save();
    res.json({ message: 'Deposit request submitted for approval', transaction });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

exports.withdraw = async (req, res) => {
  try {
    const { amount } = req.body;
    const user = await User.findById(req.userId);
    
    if (amount < parseInt(process.env.MIN_WITHDRAWAL)) {
      return res.status(400).json({ message: `Minimum withdrawal is ₦${process.env.MIN_WITHDRAWAL}` });
    }

    if (user.balance < amount) {
      return res.status(400).json({ message: 'Insufficient balance' });
    }

    const lastWithdrawal = await Transaction.findOne({
      userId: req.userId,
      type: 'withdrawal',
      status: 'approved',
      createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
    });

    if (lastWithdrawal) {
      return res.status(400).json({ message: 'One withdrawal per week allowed' });
    }

    user.balance -= amount;
    await user.save();

    const transaction = new Transaction({
      userId: req.userId,
      type: 'withdrawal',
      amount,
      status: 'pending'
    });

    await transaction.save();
    res.json({ message: 'Withdrawal request submitted', transaction });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};
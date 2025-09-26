const Transaction = require('../models/Transaction');
const User = require('../models/User');

exports.deposit = async (req, res) => {
  try {
    const { amount } = req.body;
    const minDeposit = parseInt(process.env.MIN_DEPOSIT);
    const maxDeposit = parseInt(process.env.MAX_DEPOSIT);

    if (amount < minDeposit || amount > maxDeposit) {
      return res.status(400).json({
        success: false,
        message: `Amount must be between ₦${minDeposit} and ₦${maxDeposit}`
      });
    }

    const transaction = new Transaction({
      userId: req.userId,
      type: 'deposit',
      amount,
      status: 'pending'
    });

    await transaction.save();
    
    res.json({
      success: true,
      message: 'Deposit request submitted for approval',
      transaction
    });
  } catch (error) {
    console.error('Deposit error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error processing deposit'
    });
  }
};

exports.withdraw = async (req, res) => {
  try {
    const { amount } = req.body;
    const user = await User.findById(req.userId);
    
    if (amount < parseInt(process.env.MIN_WITHDRAWAL)) {
      return res.status(400).json({
        success: false,
        message: `Minimum withdrawal is ₦${process.env.MIN_WITHDRAWAL}`
      });
    }

    if (user.balance < amount) {
      return res.status(400).json({
        success: false,
        message: 'Insufficient balance'
      });
    }

    const lastWithdrawal = await Transaction.findOne({
      userId: req.userId,
      type: 'withdrawal',
      status: 'approved',
      createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
    });

    if (lastWithdrawal) {
      return res.status(400).json({
        success: false,
        message: 'One withdrawal per week allowed'
      });
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
    
    res.json({
      success: true,
      message: 'Withdrawal request submitted',
      transaction
    });
  } catch (error) {
    console.error('Withdrawal error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error processing withdrawal'
    });
  }
};

exports.getTransactions = async (req, res) => {
  try {
    const { page = 1, limit = 10, type } = req.query;
    const query = { userId: req.userId };
    
    if (type) {
      query.type = type;
    }

    const transactions = await Transaction.find(query)
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

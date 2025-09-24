const mongoose = require('mongoose');

const claimSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  claimDate: { type: Date, required: true },
  status: { type: String, enum: ['claimed', 'missed'], required: true }
}, { timestamps: true });

module.exports = mongoose.model('Claim', claimSchema);
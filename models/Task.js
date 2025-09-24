const mongoose = require('mongoose');

const taskSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: String,
  image: String,
  reward: { type: Number, required: true },
  type: { type: String, enum: ['daily', 'weekly', 'monthly', 'one-time'], required: true },
  timeFrame: {
    startDate: Date,
    endDate: Date,
    durationHours: Number,
    repeatable: Boolean
  },
  usersCompleted: [{
    userId: mongoose.Schema.Types.ObjectId,
    completedAt: Date,
    expiresAt: Date,
    evidence: String
  }],
  active: { type: Boolean, default: true },
  maxCompletions: Number,
  requiredLevel: { type: String, enum: ['Bronze', 'Silver', 'Gold'], default: 'Bronze' }
}, { timestamps: true });

module.exports = mongoose.model('Task', taskSchema);
const Task = require('../models/Task');
const User = require('../models/User');

exports.completeTask = async (req, res) => {
  try {
    const task = await Task.findById(req.params.taskId);
    const user = await User.findById(req.userId);

    if (!task || !task.active) return res.status(404).json({ message: 'Task not found' });
    if (user.investment.tier !== task.requiredLevel) {
      return res.status(400).json({ message: 'Investment tier requirement not met' });
    }

    const alreadyCompleted = task.usersCompleted.some(comp => 
      comp.userId.toString() === req.userId && comp.expiresAt > new Date()
    );

    if (alreadyCompleted) return res.status(400).json({ message: 'Task already completed' });

    user.balance += task.reward;
    user.tasksCompleted.push({
      taskId: task._id,
      completedAt: new Date(),
      expiresAt: calculateExpiry(task.type)
    });

    task.usersCompleted.push({
      userId: user._id,
      completedAt: new Date(),
      expiresAt: calculateExpiry(task.type)
    });

    await user.save();
    await task.save();

    res.json({ message: 'Task completed successfully', reward: task.reward });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

function calculateExpiry(type) {
  const expires = new Date();
  switch (type) {
    case 'daily': expires.setDate(expires.getDate() + 1); break;
    case 'weekly': expires.setDate(expires.getDate() + 7); break;
    case 'monthly': expires.setMonth(expires.getMonth() + 1); break;
    default: expires.setFullYear(expires.getFullYear() + 100);
  }
  return expires;
}
const Task = require('../models/Task');
const User = require('../models/User');

exports.getTasks = async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    const tasks = await Task.find({ active: true });

    const tasksWithStatus = tasks.map(task => {
      const completed = task.usersCompleted.some(comp => 
        comp.userId.toString() === req.userId && comp.expiresAt > new Date()
      );
      
      const canComplete = user.investment.tier === task.requiredLevel && !completed;
      
      return {
        ...task.toObject(),
        completed,
        canComplete
      };
    });

    res.json({
      success: true,
      tasks: tasksWithStatus
    });
  } catch (error) {
    console.error('Get tasks error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error retrieving tasks'
    });
  }
};

exports.completeTask = async (req, res) => {
  try {
    const task = await Task.findById(req.params.taskId);
    const user = await User.findById(req.userId);

    if (!task || !task.active) {
      return res.status(404).json({
        success: false,
        message: 'Task not found'
      });
    }

    if (user.investment.tier !== task.requiredLevel) {
      return res.status(400).json({
        success: false,
        message: 'Investment tier requirement not met'
      });
    }

    const alreadyCompleted = task.usersCompleted.some(comp => 
      comp.userId.toString() === req.userId && comp.expiresAt > new Date()
    );

    if (alreadyCompleted) {
      return res.status(400).json({
        success: false,
        message: 'Task already completed'
      });
    }

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

    res.json({
      success: true,
      message: 'Task completed successfully',
      reward: task.reward,
      newBalance: user.balance
    });
  } catch (error) {
    console.error('Complete task error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error completing task'
    });
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

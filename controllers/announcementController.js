const Announcement = require('../models/Announcement');

exports.getActiveAnnouncements = async (req, res) => {
  try {
    const announcements = await Announcement.find({
      startsAt: { $lte: new Date() },
      endsAt: { $gte: new Date() }
    }).sort({ important: -1, createdAt: -1 });

    res.json({
      success: true,
      announcements
    });
  } catch (error) {
    console.error('Get announcements error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error retrieving announcements'
    });
  }
};

exports.createAnnouncement = async (req, res) => {
  try {
    const { title, message, link, important, startsAt, endsAt } = req.body;
    
    const announcement = new Announcement({
      title,
      message,
      link,
      important: important === 'true',
      startsAt: new Date(startsAt),
      endsAt: new Date(endsAt)
    });

    await announcement.save();
    
    res.json({
      success: true,
      message: 'Announcement created successfully',
      announcement
    });
  } catch (error) {
    console.error('Create announcement error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error creating announcement'
    });
  }
};

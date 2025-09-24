const Announcement = require('../models/Announcement');

exports.getActiveAnnouncements = async (req, res) => {
  try {
    const announcements = await Announcement.find({
      startsAt: { $lte: new Date() },
      endsAt: { $gte: new Date() }
    }).sort({ important: -1, createdAt: -1 });

    res.json(announcements);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
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
    res.status(201).json({ message: 'Announcement created successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};
const mongoose = require('mongoose');

const announcementSchema = new mongoose.Schema({
  title: { type: String, required: true },
  message: String,
  image: String,
  link: String,
  startsAt: Date,
  endsAt: Date,
  important: { type: Boolean, default: false }
}, { timestamps: true });

module.exports = mongoose.model('Announcement', announcementSchema);
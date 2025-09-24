const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
  adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  action: { type: String, required: true },
  targetType: String,
  targetId: mongoose.Schema.Types.ObjectId,
  details: Object,
  ipAddress: String
}, { timestamps: true });

module.exports = mongoose.model('AuditLog', auditLogSchema);
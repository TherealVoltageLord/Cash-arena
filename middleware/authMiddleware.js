const jwt = require('jsonwebtoken');

exports.authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Access token required' });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.userId = decoded.userId;
    next();
  });
};

exports.requireAdmin = (req, res, next) => {
  User.findById(req.userId).then(user => {
    if (!user || !['admin', 'superadmin'].includes(user.role)) {
      return res.status(403).json({ message: 'Admin access required' });
    }
    next();
  });
};
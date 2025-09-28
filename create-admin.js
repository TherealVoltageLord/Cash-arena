require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

async function createSuperAdmin() {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('Connected to MongoDB');

    const User = require('./models/User');
    
    // Check if super admin already exists
    const existingAdmin = await User.findOne({ role: 'superadmin' });
    if (existingAdmin) {
      console.log('Super admin already exists:', existingAdmin.email);
      process.exit(0);
    }

    // Create super admin
    const hashedPassword = await bcrypt.hash('Voltage66', 12);
    
    const superAdmin = new User({
      username: 'Volt-admin',
      email: ' odunayoayinla23@gmail.com',
      password: hashedPassword,
      verified: true,
      role: 'superadmin',
      balance: 1000,
      investment: {
        amount: 0,
        streak: 0,
        tier: 'Bronze'
      },
      referralCode: 'SUPERADMIN',
      lastIP: '127.0.0.1'
    });

    await superAdmin.save();
    console.log('✅ Super admin created successfully!');
    console.log('Email: admin@casharena.com');
    console.log('Password: admin123');
    console.log('Please change the password after first login!');
    
    process.exit(0);
  } catch (error) {
    console.error('Error creating super admin:', error);
    process.exit(1);
  }
}

createSuperAdmin();

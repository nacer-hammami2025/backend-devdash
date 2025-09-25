const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
require('dotenv').config();

async function createAdmin() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('✅ MongoDB connected');

        // D'abord, supprimons les anciens utilisateurs admin
        await User.deleteMany({ $or: [
            { email: 'admin@devdash.com' },
            { role: 'admin' }
        ]});

        // Créer le nouvel admin
        const adminPass = await bcrypt.hash('admin123', 10);
        const admin = await User.create({
            username: 'admin',
            email: 'admin@devdash.com',
            password: adminPass,
            role: 'admin'
        });

        console.log('✅ Admin user created successfully:', admin);
        process.exit(0);
    } catch (error) {
        console.error('❌ Error:', error);
        process.exit(1);
    }
}

createAdmin();

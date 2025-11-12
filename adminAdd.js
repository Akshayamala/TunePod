const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const saltRounds = 10;

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/TunePodDB')
    .then(() => console.log('✅ Connected to MongoDB'))
    .catch(err => {
        console.error('❌ MongoDB Connection Error:', err);
        process.exit(1);
    });

// User Schema
const userSchema = new mongoose.Schema({
    firstname: { type: String, required: true },
    lastname: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
    favoritePodcasts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Podcast' }],
    playlists: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Playlist' }]
});
const User = mongoose.model('User', userSchema);

async function updateAdmin() {
    try {
        // Hash the password
        const password = 'Ak_123';
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Update the user
        const result = await User.updateOne(
            { email: 'ak@gmail.com' },
            { $set: { isAdmin: true, password: hashedPassword } }
        );

        if (result.matchedCount === 0) {
            console.log('❌ No user found with email: ak@gmail.com');
        } else if (result.modifiedCount === 0) {
            console.log('✅ User found, but no changes were made (isAdmin and password already set)');
        } else {
            console.log('✅ User updated successfully: isAdmin set to true, password updated');
        }
    } catch (error) {
        console.error('❌ Error updating user:', error);
    } finally {
        // Close the MongoDB connection
        await mongoose.connection.close();
        console.log('✅ MongoDB connection closed');
    }
}

// Run the update
updateAdmin();
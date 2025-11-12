const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: 'http://localhost:4200',
        methods: ['GET', 'POST', 'PUT', 'DELETE'],
        credentials: true
    }
});
const saltRounds = 10;

// Middleware
app.use(express.json());
app.use(cors({
    origin: 'http://localhost:4200',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/TunePodDB')
    .then(() => console.log('✅ MongoDB Connected to TunePodDB'))
    .catch(err => console.error('❌ MongoDB Connection Error:', err));

// Schemas
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

const podcastSchema = new mongoose.Schema({
    name: { type: String, required: true },
    creator: { type: String, required: true },
    category: { type: String, required: true },
    description: { type: String },
    audioURL: { type: String, required: true },
    imageURL: { type: String },
    ratings: [{
        userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
        rating: { type: Number, required: true, min: 1, max: 5 }
    }],
    averageRating: { type: Number, default: 0 }
});
const Podcast = mongoose.model('Podcast', podcastSchema);

const playlistSchema = new mongoose.Schema({
    title: { type: String, required: true },
    creator: { type: String, required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    podcasts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Podcast' }],
    imageURL: { type: String }
});
const Playlist = mongoose.model('Playlist', playlistSchema);

const notificationSchema = new mongoose.Schema({
    message: { type: String, required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    podcastId: { type: mongoose.Schema.Types.ObjectId, ref: 'Podcast' },
    read: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});
const Notification = mongoose.model('Notification', notificationSchema);

// Middleware
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: '❌ No token provided' });
    }
    try {
        const decoded = jwt.verify(token, 'your_secret_key');
        req.user = decoded;
        next();
    } catch (error) {
        console.error('❌ Invalid token:', error);
        return res.status(401).json({ error: '❌ Invalid or expired token' });
    }
};

const verifyAdmin = (req, res, next) => {
    if (!req.user.isAdmin) {
        return res.status(403).json({ error: '❌ Admin access required' });
    }
    next();
};

// Socket.IO connection
io.on('connection', (socket) => {
    console.log('A user connected:', socket.id);
    socket.on('join', (userId) => {
        socket.join(userId);
    });
    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.id);
    });
});

// Routes
app.get('/', (req, res) => {
    res.send('🚀 Server is running! Welcome to the TunePod API.');
});

// Register
app.post('/register', async (req, res) => {
    try {
        const { email, password, firstname, lastname, isAdmin } = req.body;
        console.log('📥 Received registration data:', req.body);

        if (!email || !password || !firstname || !lastname) {
            return res.status(400).json({ message: 'All fields (email, password, firstname, lastname) are required' });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Email already registered' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            email,
            password: hashedPassword,
            firstname,
            lastname,
            isAdmin: isAdmin || false
        });

        await user.save();
        res.status(201).json({
            message: '✅ User registered successfully',
            user: { email, firstname, lastname, isAdmin: user.isAdmin }
        });
    } catch (error) {
        console.error('❌ Error registering user:', error);
        res.status(400).json({ message: 'Error registering user', error: error.message });
    }
});

// Login
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: '📌 Email and password are required' });
        }
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: '❌ Invalid credentials' });
        }
        const token = jwt.sign(
            { userId: user._id, email: user.email, isAdmin: user.isAdmin },
            'your_secret_key',
            { expiresIn: '1h' }
        );
        res.status(200).json({
            message: 'Login successful',
            token,
            user: {
                email: user.email,
                firstname: user.firstname,
                lastname: user.lastname,
                isAdmin: user.isAdmin
            }
        });
    } catch (error) {
        console.error('❌ Error logging in user:', error);
        res.status(500).json({ message: 'Server error during login', error });
    }
});

// Get User Profile (Protected)
app.get('/api/user/profile', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password').populate('playlists');
        if (!user) {
            return res.status(404).json({ error: '❌ User not found' });
        }
        res.status(200).json({
            message: '✅ Profile fetched successfully',
            user: {
                email: user.email,
                firstname: user.firstname,
                lastname: user.lastname,
                isAdmin: user.isAdmin,
                favoritePodcasts: user.favoritePodcasts,
                playlists: user.playlists
            }
        });
    } catch (error) {
        console.error('❌ Error fetching profile:', error);
        res.status(500).json({ error: 'Server error fetching profile' });
    }
});

// Update User Profile (Protected)
app.put('/api/user/profile', verifyToken, async (req, res) => {
    try {
        const { firstname, lastname, email, password } = req.body;
        if (!firstname || !lastname || !email) {
            return res.status(400).json({ error: '❌ Firstname, lastname, and email are required' });
        }
        const updateData = { firstname, lastname, email };
        if (password) {
            updateData.password = await bcrypt.hash(password, 10);
        }
        const user = await User.findByIdAndUpdate(
            req.user.userId,
            updateData,
            { new: true, runValidators: true }
        ).select('-password');
        if (!user) {
            return res.status(404).json({ error: '❌ User not found' });
        }
        res.status(200).json({
            message: '✅ Profile updated successfully',
            user: {
                email: user.email,
                firstname: user.firstname,
                lastname: user.lastname,
                isAdmin: user.isAdmin
            }
        });
    } catch (error) {
        console.error('❌ Error updating profile:', error);
        if (error.code === 11000) {
            return res.status(400).json({ error: '❌ Email already in use' });
        }
        res.status(500).json({ error: 'Server error updating profile' });
    }
});

// Get all podcasts (Admin only)
app.get('/api/admin', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const podcasts = await Podcast.find();
        res.status(200).json(podcasts);
    } catch (error) {
        console.error('❌ Error fetching podcasts:', error);
        res.status(500).json({ message: 'Error fetching podcasts', error });
    }
});

// Add a new podcast (Admin only)
app.post('/api/admin', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { name, creator, category, description, audioURL, imageURL } = req.body;
        if (!name || !creator || !category || !audioURL) {
            return res.status(400).json({ message: 'Name, creator, category, and audioURL are required' });
        }
        const podcast = new Podcast({
            name,
            creator,
            category,
            description,
            audioURL,
            imageURL
        });
        const savedPodcast = await podcast.save();

        // Create notifications for all users
        const users = await User.find({ isAdmin: false });
        const notifications = users.map(user => ({
            message: `New podcast "${name}" added by ${creator}`,
            userId: user._id,
            podcastId: savedPodcast._id,
            read: false
        }));
        await Notification.insertMany(notifications);

        // Notify all users via Socket.IO
        users.forEach(user => {
            io.to(user._id.toString()).emit('newNotification', {
                message: `New podcast "${name}" added by ${creator}`,
                podcastId: savedPodcast._id,
                createdAt: new Date()
            });
        });

        res.status(201).json(savedPodcast);
    } catch (error) {
        console.error('❌ Error saving podcast:', error);
        res.status(500).json({ message: 'Error saving podcast', error });
    }
});

// Get user notifications (Protected)
app.get('/api/user/notifications', verifyToken, async (req, res) => {
    try {
        const notifications = await Notification.find({ userId: req.user.userId })
            .sort({ createdAt: -1 })
            .populate('podcastId');
        res.status(200).json(notifications);
    } catch (error) {
        console.error('❌ Error fetching notifications:', error);
        res.status(500).json({ error: 'Server error fetching notifications' });
    }
});

// Mark notification as read (Protected)
app.put('/api/user/notifications/:id/read', verifyToken, async (req, res) => {
    try {
        const notification = await Notification.findOne({
            _id: req.params.id,
            userId: req.user.userId
        });
        if (!notification) {
            return res.status(404).json({ error: 'Notification not found' });
        }
        notification.read = true;
        await notification.save();
        res.status(200).json({ message: 'Notification marked as read' });
    } catch (error) {
        console.error('❌ Error marking notification as read:', error);
        res.status(500).json({ error: 'Server error marking notification as read' });
    }
});

// Update a podcast (Admin only)
app.put('/api/admin/:id', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({ message: 'Invalid podcast ID' });
        }
        const { name, creator, category, description, audioURL, imageURL } = req.body;
        const updatedPodcast = await Podcast.findByIdAndUpdate(
            id,
            { name, creator, category, description, audioURL, imageURL },
            { new: true }
        );
        if (!updatedPodcast) return res.status(404).json({ message: 'Podcast not found' });
        res.status(200).json(updatedPodcast);
    } catch (error) {
        console.error('❌ Error updating podcast:', error);
        res.status(500).json({ message: 'Error updating podcast', error });
    }
});

// Delete a podcast (Admin only)
app.delete('/api/admin/:id', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({ message: 'Invalid podcast ID' });
        }
        const deleted = await Podcast.findByIdAndDelete(id);
        if (!deleted) return res.status(404).json({ message: 'Podcast not found' });
        res.status(204).send();
    } catch (error) {
        console.error('❌ Error deleting podcast:', error);
        res.status(500).json({ message: 'Error deleting podcast', error });
    }
});

// Get podcasts by category (Public)
app.get('/api/podcasts/category/:category', async (req, res) => {
    try {
        const { category } = req.params;
        const podcasts = await Podcast.find({ category });
        res.status(200).json(podcasts);
    } catch (error) {
        console.error('❌ Error fetching podcasts by category:', error);
        res.status(500).json({ message: 'Error fetching podcasts by category', error });
    }
});

// Add to favorites (Protected)
app.post('/api/user/favorites', verifyToken, async (req, res) => {
    try {
        const { podcastId } = req.body;
        if (!mongoose.Types.ObjectId.isValid(podcastId)) {
            return res.status(400).json({ error: 'Invalid podcast ID' });
        }
        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        if (!user.favoritePodcasts.includes(podcastId)) {
            user.favoritePodcasts.push(podcastId);
            await user.save();
        }
        res.status(200).json({ message: 'Podcast added to favorites' });
    } catch (error) {
        console.error('❌ Error adding to favorites:', error);
        res.status(500).json({ error: 'Server error adding to favorites' });
    }
});

// Remove from favorites (Protected)
app.delete('/api/user/favorites/:podcastId', verifyToken, async (req, res) => {
    try {
        const { podcastId } = req.params;
        if (!mongoose.Types.ObjectId.isValid(podcastId)) {
            return res.status(400).json({ error: 'Invalid podcast ID' });
        }
        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        user.favoritePodcasts = user.favoritePodcasts.filter(
            (id) => id.toString() !== podcastId
        );
        await user.save();
        res.status(200).json({ message: 'Podcast removed from favorites' });
    } catch (error) {
        console.error('❌ Error removing from favorites:', error);
        res.status(500).json({ error: 'Server error removing from favorites' });
    }
});

// Get favorite podcasts (Protected)
app.get('/api/user/favorites', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).populate('favoritePodcasts');
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.status(200).json(user.favoritePodcasts);
    } catch (error) {
        console.error('❌ Error fetching favorite podcasts:', error);
        res.status(500).json({ error: 'Server error fetching favorite podcasts' });
    }
});

// Get all podcasts (Public)
app.get('/api/podcasts', async (req, res) => {
    try {
        const podcasts = await Podcast.find();
        res.status(200).json(podcasts);
    } catch (error) {
        console.error('❌ Error fetching podcasts:', error);
        res.status(500).json({ message: 'Error fetching podcasts', error });
    }
});

// Get podcast by ID (Public)
app.get('/api/podcasts/:id', async (req, res) => {
    try {
        const { id } = req.params;
        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({ message: 'Invalid podcast ID' });
        }
        const podcast = await Podcast.findById(id);
        if (!podcast) {
            return res.status(404).json({ message: 'Podcast not found' });
        }
        res.status(200).json(podcast);
    } catch (error) {
        console.error('❌ Error fetching podcast:', error);
        res.status(500).json({ message: 'Error fetching podcast', error });
    }
});

// Create a playlist (Protected)
app.post('/api/user/playlists', verifyToken, async (req, res) => {
    try {
        const { title, podcastIds, imageURL } = req.body;
        if (!title || !podcastIds || !Array.isArray(podcastIds)) {
            return res.status(400).json({ error: 'Title and podcastIds (array) are required' });
        }
        for (const id of podcastIds) {
            if (!mongoose.Types.ObjectId.isValid(id)) {
                return res.status(400).json({ error: `Invalid podcast ID: ${id}` });
            }
        }
        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        const playlist = new Playlist({
            title,
            creator: user.firstname,
            userId: user._id,
            podcasts: podcastIds,
            imageURL: imageURL || 'https://via.placeholder.com/150'
        });
        const savedPlaylist = await playlist.save();
        user.playlists.push(savedPlaylist._id);
        await user.save();
        res.status(201).json({ message: 'Playlist created successfully', playlist: savedPlaylist });
    } catch (error) {
        console.error('❌ Error creating playlist:', error);
        res.status(500).json({ error: 'Server error creating playlist' });
    }
});

// Add podcasts to a playlist (Protected)
app.post('/api/user/playlists/:playlistId/podcasts', verifyToken, async (req, res) => {
    try {
        const { playlistId } = req.params;
        const { podcastIds } = req.body;
        if (!mongoose.Types.ObjectId.isValid(playlistId)) {
            return res.status(400).json({ error: 'Invalid playlist ID' });
        }
        if (!podcastIds || !Array.isArray(podcastIds)) {
            return res.status(400).json({ error: 'podcastIds (array) is required' });
        }
        for (const id of podcastIds) {
            if (!mongoose.Types.ObjectId.isValid(id)) {
                return res.status(400).json({ error: `Invalid podcast ID: ${id}` });
            }
        }
        const playlist = await Playlist.findById(playlistId);
        if (!playlist) {
            return res.status(404).json({ error: 'Playlist not found' });
        }
        if (playlist.userId.toString() !== req.user.userId) {
            return res.status(403).json({ error: 'Unauthorized to modify this playlist' });
        }
        // Add only new podcast IDs
        podcastIds.forEach((id) => {
            if (!playlist.podcasts.includes(id)) {
                playlist.podcasts.push(id);
            }
        });
        await playlist.save();
        res.status(200).json({ message: 'Podcasts added to playlist' });
    } catch (error) {
        console.error('❌ Error adding podcasts to playlist:', error);
        res.status(500).json({ error: 'Server error adding podcasts to playlist' });
    }
});

// Get user playlists (Protected)
app.get('/api/user/playlists', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).populate({
            path: 'playlists',
            populate: { path: 'podcasts' }
        });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.status(200).json(user.playlists);
    } catch (error) {
        console.error('❌ Error fetching playlists:', error);
        res.status(500).json({ error: 'Server error fetching playlists' });
    }
});

// Delete a playlist (Protected)
app.delete('/api/user/playlists/:playlistId', verifyToken, async (req, res) => {
    try {
        const { playlistId } = req.params;
        if (!mongoose.Types.ObjectId.isValid(playlistId)) {
            return res.status(400).json({ error: 'Invalid playlist ID' });
        }
        const playlist = await Playlist.findById(playlistId);
        if (!playlist) {
            return res.status(404).json({ error: 'Playlist not found' });
        }
        if (playlist.userId.toString() !== req.user.userId) {
            return res.status(403).json({ error: 'Unauthorized to delete this playlist' });
        }
        await Playlist.findByIdAndDelete(playlistId);
        const user = await User.findById(req.user.userId);
        user.playlists = user.playlists.filter(id => id.toString() !== playlistId);
        await user.save();
        res.status(200).json({ message: 'Playlist deleted successfully' });
    } catch (error) {
        console.error('❌ Error deleting playlist:', error);
        res.status(500).json({ error: 'Server error deleting playlist' });
    }
});

// Remove a podcast from a playlist (Protected)
app.delete('/api/user/playlists/:playlistId/podcasts/:podcastId', verifyToken, async (req, res) => {
    try {
        const { playlistId, podcastId } = req.params;
        if (!mongoose.Types.ObjectId.isValid(playlistId) || !mongoose.Types.ObjectId.isValid(podcastId)) {
            return res.status(400).json({ error: 'Invalid playlist or podcast ID' });
        }
        const playlist = await Playlist.findById(playlistId);
        if (!playlist) {
            return res.status(404).json({ error: 'Playlist not found' });
        }
        if (playlist.userId.toString() !== req.user.userId) {
            return res.status(403).json({ error: 'Unauthorized to modify this playlist' });
        }
        playlist.podcasts = playlist.podcasts.filter(id => id.toString() !== podcastId);
        await playlist.save();
        res.status(200).json({ message: 'Podcast removed from playlist' });
    } catch (error) {
        console.error('❌ Error removing podcast from playlist:', error);
        res.status(500).json({ error: 'Server error removing podcast from playlist' });
    }
});

// Submit or update a podcast rating (Protected)
app.post('/api/podcasts/:id/rate', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { rating } = req.body;

        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({ error: 'Invalid podcast ID' });
        }
        if (!rating || rating < 1 || rating > 5) {
            return res.status(400).json({ error: 'Rating must be between 1 and 5' });
        }

        const podcast = await Podcast.findById(id);
        if (!podcast) {
            return res.status(404).json({ error: 'Podcast not found' });
        }

        // Check if user has already rated
        const existingRating = podcast.ratings.find(
            r => r.userId.toString() === req.user.userId
        );

        if (existingRating) {
            // Update existing rating
            existingRating.rating = rating;
        } else {
            // Add new rating
            podcast.ratings.push({ userId: req.user.userId, rating });
        }

        // Calculate average rating
        const totalRatings = podcast.ratings.length;
        const sumRatings = podcast.ratings.reduce((sum, r) => sum + r.rating, 0);
        podcast.averageRating = totalRatings > 0 ? sumRatings / totalRatings : 0;

        await podcast.save();

        res.status(200).json({
            message: 'Rating submitted successfully',
            averageRating: podcast.averageRating,
            totalRatings
        });
    } catch (error) {
        console.error('❌ Error submitting rating:', error);
        res.status(500).json({ error: 'Server error submitting rating' });
    }
});

// Get podcast ratings (Public)
app.get('/api/podcasts/:id/ratings', async (req, res) => {
    try {
        const { id } = req.params;
        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({ error: 'Invalid podcast ID' });
        }
        const podcast = await Podcast.findById(id).select('ratings averageRating');
        if (!podcast) {
            return res.status(404).json({ error: 'Podcast not found' });
        }
        res.status(200).json({
            averageRating: podcast.averageRating,
            totalRatings: podcast.ratings.length,
            ratings: podcast.ratings
        });
    } catch (error) {
        console.error('❌ Error fetching ratings:', error);
        res.status(500).json({ error: 'Server error fetching ratings' });
    }
});

// Start the Server
const PORT = 3000;
server.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});
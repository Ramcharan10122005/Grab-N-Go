import express from "express";
import connectDB from "./db.js";
import path from "path";
import Register from "./models/registerSchema.js";
import FoodItem from "./models/foodItemSchema.js";
import Order from "./models/orderSchema.js";
import session from "express-session"
import bcrypt from "bcrypt"
import multer from "multer";
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import Razorpay from 'razorpay';
import crypto from 'crypto';
import Admin from "./models/adminSchema.js";
import ContactMessage from "./models/contactMessageSchema.js";

// Import order routes
import orderRoutes from './routes/orderRoutes.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const port = 3000;

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = path.join(__dirname, 'public', 'uploads');
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB limit
    },
    fileFilter: function (req, file, cb) {
        const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
        if (!allowedTypes.includes(file.mimetype)) {
            const error = new Error('Invalid file type. Only JPEG, PNG and GIF are allowed.');
            error.code = 'INVALID_FILE_TYPE';
            return cb(error, false);
        }
        cb(null, true);
    }
});

connectDB();

app.set("view engine", "ejs");

app.set("views", path.join(process.cwd(), "views"));

app.use(express.static(path.join(process.cwd(), "public")));
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
    secret: "your_secret_key",
    resave: false,
    saveUninitialized: true,
}));

// Middleware to check if user is authenticated
const isAuthenticated = (req, res, next) => {
    if (req.session.user) {
        next();
    } else {
        res.redirect('/login');
    }
};

// Middleware to check if user is a vendor
const isVendor = (req, res, next) => {
    console.log('Checking vendor status for session:', req.session.user);
    if (req.session.user && req.session.user.role === 'vendor') {
        console.log('Vendor access granted for:', req.session.user.username);
        next();
    } else {
        console.log('Vendor access denied');
        res.status(403).send("Access denied. Vendor privileges required.");
    }
};

// Middleware to check if user is an admin
const isAdmin = (req, res, next) => {
    if (req.session.user && req.session.user.role === 'admin') {
        next();
    } else {
        res.status(403).send("Access denied. Admin privileges required.");
    }
};

// Initialize Razorpay
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET
});

app.get("/", (req, res) => {
    res.render("index", { user: req.session.user || null });
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.get('/vendor-login', (req, res) => {
    res.render('vendor-login');
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.get('/menu', isAuthenticated, (req, res) => {
    res.render('menu', { user: req.session.user });
});

app.get('/orders', isAuthenticated, (req, res) => {
    res.render('orders', { user: req.session.user });
});

app.get('/settings', isAuthenticated, (req, res) => {
    res.render('settings', { user: req.session.user });
});

app.get("/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send("Error logging out");
        }
        res.redirect("/");
    });
});

app.post("/login", async (req, res) => {
    const { Username, Password } = req.body;

    try {
        const user = await Register.findOne({ username: Username });

        if (!user) {
            return res.status(404).send("User not found");
        }

        const match = await bcrypt.compare(Password, user.password);
        if (!match) {
            return res.status(401).send("Invalid password");
        }

        req.session.user = {
            id: user._id,
            username: user.username,
            role: user.role,
        };

        res.redirect('/menu');
    } catch (err) {
        console.error("Error during login:", err);
        res.status(500).send("Server error");
    }
});

app.post("/register", async (req, res) => {
    const { name, email, username, password, role, businessName, businessAddress, phone } = req.body;

    try {
        // Check if username already exists
        const existingUser = await Register.findOne({ username });
        if (existingUser) {
            return res.status(400).send("Username already exists");
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user object
        const userData = {
            name,
            email,
            username,
            password: hashedPassword,
            role: role || 'user',
            phone
        };

        // Add vendor-specific fields if role is vendor
        if (role === 'vendor') {
            if (!businessName || !businessAddress) {
                return res.status(400).send("Business name and address are required for vendor registration");
            }
            userData.businessName = businessName;
            userData.businessAddress = businessAddress;
        }

        // Create new user
        const newUser = new Register(userData);
        await newUser.save();

        // Set session
        req.session.user = {
            id: newUser._id,
            username: newUser.username,
            role: newUser.role
        };

        // Redirect based on role
        if (role === 'vendor') {
            res.redirect('/menu');
        } else {
            res.redirect('/');
        }
    } catch (err) {
        console.error("Registration error:", err);
        res.status(500).send("Registration failed. Please try again.");
    }
});

app.post('/vendor-login', async (req, res) => {
    const { Username, Password } = req.body;

    try {
        console.log('Attempting vendor login for:', Username);
        
        // Find user with vendor role
        const user = await Register.findOne({ username: Username, role: 'vendor' });

        if (!user) {
            console.log('Vendor not found:', Username);
            return res.status(404).send("Vendor not found. Please check your credentials or register as a vendor.");
        }

        const match = await bcrypt.compare(Password, user.password);
        if (!match) {
            console.log('Invalid password for vendor:', Username);
            return res.status(401).send("Invalid password");
        }

        // Set session with complete user data
        req.session.user = {
            id: user._id,
            username: user.username,
            role: user.role,
            email: user.email,
            name: user.name,
            businessName: user.businessName,
            businessAddress: user.businessAddress
        };

        console.log('Vendor login successful:', Username);
        res.redirect('/menu');
    } catch (err) {
        console.error("Error during vendor login:", err);
        res.status(500).send("Server error during login. Please try again.");
    }
});

// Food Item Routes
app.post("/api/food-items", isAuthenticated, isVendor, upload.single('image'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'Image is required' });
        }

        const foodItem = new FoodItem({
            ...req.body,
            vendorId: req.session.user.id,
            image: `/uploads/${req.file.filename}` // Store the path to the uploaded image
        });
        await foodItem.save();
        res.status(201).json(foodItem);
    } catch (err) {
        if (err.code === 'INVALID_FILE_TYPE') {
            return res.status(400).json({ error: err.message });
        }
        res.status(400).json({ error: err.message });
    }
});

app.get("/api/food-items", async (req, res) => {
    try {
        let query = { isAvailable: true };
        
        // If user is a vendor, only show their items
        if (req.session.user && req.session.user.role === 'vendor') {
            query.vendorId = req.session.user.id;
        }
        
        const foodItems = await FoodItem.find(query);
        res.json(foodItems);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get("/api/food-items/:id", async (req, res) => {
    try {
        const foodItem = await FoodItem.findById(req.params.id);
        if (!foodItem) {
            return res.status(404).json({ error: "Food item not found" });
        }
        res.json(foodItem);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put("/api/food-items/:id", isAuthenticated, isVendor, upload.single('image'), async (req, res) => {
    try {
        const foodItem = await FoodItem.findById(req.params.id);
        if (!foodItem) {
            return res.status(404).json({ error: "Food item not found" });
        }
        if (foodItem.vendorId.toString() !== req.session.user.id) {
            return res.status(403).json({ error: "Unauthorized access" });
        }

        // Update fields from request body
        const updateData = { ...req.body };
        
        // If a new image was uploaded, update the image path
        if (req.file) {
            updateData.image = `/uploads/${req.file.filename}`;
        }

        // Update the food item
        Object.assign(foodItem, updateData);
        await foodItem.save();
        
        res.json(foodItem);
    } catch (err) {
        console.error('Error updating food item:', err);
        res.status(500).json({ error: err.message });
    }
});

app.delete("/api/food-items/:id", isAuthenticated, isVendor, async (req, res) => {
    try {
        const foodItem = await FoodItem.findById(req.params.id);
        if (!foodItem) {
            return res.status(404).json({ error: "Food item not found" });
        }
        if (foodItem.vendorId.toString() !== req.session.user.id) {
            return res.status(403).json({ error: "Unauthorized access" });
        }
        await FoodItem.deleteOne({ _id: req.params.id });
        res.json({ message: "Food item deleted successfully" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Order Routes
app.post("/api/orders", isAuthenticated, async (req, res) => {
    try {
        const order = new Order({
            ...req.body,
            userId: req.session.user.id
        });
        await order.save();
        res.status(201).json(order);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

app.get("/api/orders", isAuthenticated, async (req, res) => {
    try {
        const orders = await Order.find({ userId: req.session.user.id })
            .populate('items.foodItemId')
            .populate('vendorId', 'name');
        res.json(orders);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get("/api/orders/:id", isAuthenticated, async (req, res) => {
    try {
        const order = await Order.findById(req.params.id)
            .populate('items.foodItemId')
            .populate('vendorId', 'name');
        if (!order) {
            return res.status(404).json({ error: "Order not found" });
        }
        if (order.userId.toString() !== req.session.user.id && order.vendorId.toString() !== req.session.user.id) {
            return res.status(403).json({ error: "Unauthorized access" });
        }
        res.json(order);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.patch("/api/orders/:id/status", isAuthenticated, async (req, res) => {
    try {
        const order = await Order.findById(req.params.id);
        if (!order) {
            return res.status(404).json({ error: "Order not found" });
        }
        if (order.vendorId.toString() !== req.session.user.id) {
            return res.status(403).json({ error: "Unauthorized access" });
        }
        order.status = req.body.status;
        await order.save();
        res.json(order);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Settings Routes
app.post('/settings/profile', isAuthenticated, async (req, res) => {
    try {
        const { name, email, username, phone, street, city, state, zipCode } = req.body;
        
        // Validate required fields
        if (!name || !email || !username) {
            return res.status(400).send("Name, email, and username are required fields");
        }
        
        // Find user and update profile
        const user = await Register.findById(req.session.user.id);
        
        if (!user) {
            return res.status(404).send("User not found");
        }
        
        // Update basic fields
        user.name = name.trim();
        user.email = email.trim();
        user.username = username.trim();
        user.phone = phone ? phone.trim() : undefined;
        
        // Update address
        user.address = {
            street: street ? street.trim() : '',
            city: city ? city.trim() : '',
            state: state ? state.trim() : '',
            zipCode: zipCode ? zipCode.trim() : ''
        };
        
        await user.save();
        
        // Update session with new data
        req.session.user = {
            id: user._id,
            username: user.username,
            role: user.role,
            email: user.email
        };
        
        res.redirect('/settings');
    } catch (err) {
        console.error("Error updating profile:", err);
        // Send a more user-friendly error message
        res.status(500).send("Unable to update profile. Please ensure all required fields are filled correctly.");
    }
});

app.post('/settings/password', isAuthenticated, async (req, res) => {
    try {
        const { currentPassword, newPassword, confirmPassword } = req.body;
        
        // Check if passwords match
        if (newPassword !== confirmPassword) {
            return res.status(400).send("New passwords do not match");
        }
        
        // Find user
        const user = await Register.findById(req.session.user.id);
        
        if (!user) {
            return res.status(404).send("User not found");
        }
        
        // Verify current password
        const match = await bcrypt.compare(currentPassword, user.password);
        if (!match) {
            return res.status(401).send("Current password is incorrect");
        }
        
        // Hash and update new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        await user.save();
        
        res.redirect('/settings');
    } catch (err) {
        console.error("Error updating password:", err);
        res.status(500).send("Error updating password");
    }
});

app.post('/settings/preferences', isAuthenticated, async (req, res) => {
    try {
        const { emailNotifications, smsNotifications } = req.body;
        
        // Find user and update preferences
        const user = await Register.findById(req.session.user.id);
        
        if (!user) {
            return res.status(404).send("User not found");
        }
        
        // Update notification preferences
        user.preferences = {
            emailNotifications: !!emailNotifications,
            smsNotifications: !!smsNotifications
        };
        
        await user.save();
        
        res.redirect('/settings');
    } catch (err) {
        console.error("Error updating preferences:", err);
        res.status(500).send("Error updating preferences");
    }
});

// Image upload route
app.post('/api/upload', upload.single('image'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }
        
        // Create the URL for the uploaded file
        const fileUrl = `/uploads/${req.file.filename}`;
        
        res.json({
            success: true,
            message: 'File uploaded successfully',
            fileUrl: fileUrl
        });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({
            success: false,
            message: error.message || 'Error uploading file'
        });
    }
});

// Create order route
app.post('/create-order', async (req, res) => {
    try {
        console.log('Request body:', req.body);
        const { amount, currency } = req.body;
        
        if (!amount || !currency) {
            return res.status(400).json({ error: 'Amount and currency are required' });
        }

        // Convert amount to smallest currency unit (paise)
        const amountInPaise = Math.round(amount * 100);
        
        const options = {
            amount: amountInPaise,
            currency: currency,
            receipt: `receipt_${Date.now()}`,
        };
        
        const order = await razorpay.orders.create(options);
        
        res.json({ 
            orderId: order.id,
            amount: amountInPaise,
            currency: currency
        });
    } catch (error) {
        console.error('Error creating order:', error);
        res.status(500).json({ error: 'Failed to create payment order' });
    }
});

// Verify payment route
app.post('/verify-payment', async (req, res) => {
    try {
        const { razorpay_payment_id, razorpay_order_id, razorpay_signature, orderData } = req.body;
        
        if (!razorpay_payment_id || !razorpay_order_id || !razorpay_signature || !orderData) {
            return res.status(400).json({ success: false, error: 'Missing payment parameters' });
        }

        // Create the signature verification data
        const body = razorpay_order_id + "|" + razorpay_payment_id;
        const expectedSignature = crypto
            .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
            .update(body.toString())
            .digest('hex');

        // Verify the signature
        const isValidSignature = expectedSignature === razorpay_signature;

        if (isValidSignature) {
            // Create the order in our database
            const order = new Order({
                ...orderData,
                userId: req.session.user.id,
                paymentId: razorpay_payment_id,
                status: 'pending'
            });
            
            await order.save();
            
            res.json({ 
                success: true,
                message: 'Payment verified and order created successfully',
                orderId: order._id
            });
        } else {
            res.status(400).json({ 
                success: false, 
                error: 'Invalid payment signature'
            });
        }
    } catch (error) {
        console.error('Error in payment verification:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Error verifying payment'
        });
    }
});

// Use order routes
app.use('/', orderRoutes);

// Admin routes
app.get('/admin', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        res.redirect('/admin-login');
    } else {
        res.render('admin', { user: req.session.user });
    }
});

// Vendor dashboard route
app.get('/vendor-dashboard', isAuthenticated, isVendor, (req, res) => {
    res.render('vendor-dashboard', { user: req.session.user });
});

app.get('/admin-login', (req, res) => {
    res.render('admin-login');
});

app.post("/create-admin", async (req, res) => {
    try {
        const adminExists = await Admin.findOne({ username: 'Ramcharan' });
        if (adminExists) {
            return res.status(400).send("Admin user already exists");
        }

        const admin = new Admin({
            username: 'Ramcharan',
            password: 'Ramcharan@1012',
            name: 'Ramcharan',
            email: 'admin@grabngo.com',
            role: 'admin'
        });

        await admin.save();
        res.status(201).send("Admin user created successfully");
    } catch (err) {
        console.error("Error creating admin:", err);
        res.status(500).send("Error creating admin user");
    }
});

app.post("/admin-login", async (req, res) => {
    const { username, password } = req.body;

    try {
        const admin = await Admin.findOne({ username });
        
        if (!admin) {
            return res.status(401).send("Invalid admin credentials");
        }

        const isMatch = await admin.comparePassword(password);
        if (!isMatch) {
            return res.status(401).send("Invalid admin credentials");
        }

        // Update last login
        admin.lastLogin = new Date();
        await admin.save();

        req.session.user = {
            id: admin._id,
            username: admin.username,
            role: admin.role
        };
        
        res.redirect('/admin');
    } catch (err) {
        console.error("Error during admin login:", err);
        res.status(500).send("Server error");
    }
});

// Admin API routes
app.get('/api/admin/orders', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const orders = await Order.find()
            .populate('userId', 'username name email')
            .populate('vendorId', 'businessName businessAddress')
            .sort({ createdAt: -1 });
        res.json(orders);
    } catch (err) {
        console.error('Error fetching orders:', err);
        res.status(500).json({ error: 'Error fetching orders' });
    }
});

app.get('/api/admin/restaurants', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const restaurants = await Register.find({ role: 'vendor' })
            .select('username name email businessName businessAddress')
            .sort({ businessName: 1 });
        res.json(restaurants);
    } catch (err) {
        console.error('Error fetching restaurants:', err);
        res.status(500).json({ error: 'Error fetching restaurants' });
    }
});

// Add vendor earnings endpoint
app.get('/api/admin/vendors/:id/earnings', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const vendorId = req.params.id;
        
        // Find all completed orders for this vendor
        const orders = await Order.find({
            vendorId: vendorId,
            status: { $in: ['delivered', 'picked up'] }
        });
        
        // Calculate total earnings
        const totalEarnings = orders.reduce((sum, order) => sum + order.totalAmount, 0);
        
        // Count completed orders
        const completedOrders = orders.length;
        
        res.json({
            vendorId,
            totalEarnings,
            completedOrders
        });
    } catch (err) {
        console.error('Error fetching vendor earnings:', err);
        res.status(500).json({ error: 'Error fetching vendor earnings' });
    }
});

app.patch('/api/admin/orders/:id/status', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const { status } = req.body;
        const order = await Order.findById(req.params.id);
        
        if (!order) {
            return res.status(404).json({ error: 'Order not found' });
        }

        // Update order status
        order.status = status;

        // If order is marked as delivered, update vendor payment
        if (status === 'delivered' && order.vendorPayment.status === 'pending') {
            order.vendorPayment = {
                status: 'completed',
                amount: order.totalAmount,
                transferDate: new Date()
            };
        }

        await order.save();

        // Populate user and vendor details for response
        const updatedOrder = await Order.findById(order._id)
            .populate('userId', 'username name email')
            .populate('vendorId', 'businessName businessAddress');
        
        res.json(updatedOrder);
    } catch (err) {
        console.error('Error updating order status:', err);
        res.status(500).json({ error: 'Error updating order status' });
    }
});

// About route
app.get('/about', (req, res) => {
    res.render('about', { user: req.session.user || null });
});

// Contact routes
app.get('/contact', (req, res) => {
    res.render('contact', { user: req.session.user || null });
});

app.post('/contact', async (req, res) => {
    try {
        const { name, email, subject, message } = req.body;
        
        // Save the contact message to the database
        const contactMessage = new ContactMessage({
            name,
            email,
            subject,
            message
        });
        
        await contactMessage.save();
        
        res.render('contact', {
            user: req.session.user || null,
            message: 'Thank you for your message. We will get back to you soon!'
        });
    } catch (error) {
        console.error('Error processing contact form:', error);
        res.render('contact', {
            user: req.session.user || null,
            message: 'There was an error sending your message. Please try again.'
        });
    }
});

// API endpoint to get unread contact messages
app.get('/api/admin/unread-messages', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const unreadMessages = await ContactMessage.find({ isRead: false })
            .sort({ createdAt: -1 });
        
        res.json({
            count: unreadMessages.length,
            messages: unreadMessages
        });
    } catch (error) {
        console.error('Error fetching unread messages:', error);
        res.status(500).json({ error: 'Error fetching unread messages' });
    }
});

// API endpoint to mark a message as read
app.patch('/api/admin/messages/:id/read', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const message = await ContactMessage.findById(req.params.id);
        
        if (!message) {
            return res.status(404).json({ error: 'Message not found' });
        }
        
        message.isRead = true;
        await message.save();
        
        res.json({ success: true });
    } catch (error) {
        console.error('Error marking message as read:', error);
        res.status(500).json({ error: 'Error marking message as read' });
    }
});

// API endpoint to get all messages
app.get('/api/admin/messages', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const messages = await ContactMessage.find()
            .sort({ createdAt: -1 });
        
        res.json(messages);
    } catch (error) {
        console.error('Error fetching messages:', error);
        res.status(500).json({ error: 'Error fetching messages' });
    }
});

app.listen(port, () => {
    console.log("Server connected to port:", port);
});

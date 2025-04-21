const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');

// Configure multer for storing uploaded files
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'public/uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

// File filter to accept only images
const fileFilter = (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
        cb(null, true);
    } else {
        cb(new Error('Not an image! Please upload an image.'), false);
    }
};

const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    }
});

// Route to handle single file upload
router.post('/image', upload.single('image'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ message: 'No file uploaded' });
        }
        
        const imageUrl = `/uploads/${req.file.filename}`;
        res.status(200).json({ 
            message: 'File uploaded successfully',
            imageUrl: imageUrl
        });
    } catch (error) {
        res.status(500).json({ 
            message: 'Error uploading file',
            error: error.message
        });
    }
});

module.exports = router; 
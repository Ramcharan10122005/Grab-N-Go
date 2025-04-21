import mongoose from 'mongoose';

const orderSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Register',
        required: true
    },
    items: [{
        foodItemId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'FoodItem',
            required: true
        },
        quantity: {
            type: Number,
            required: true,
            min: 1
        },
        price: {
            type: Number,
            required: true
        }
    }],
    totalAmount: {
        type: Number,
        required: true
    },
    pickupTime: {
        type: Date,
        required: true
    },
    status: {
        type: String,
        enum: ['pending', 'preparing', 'ready', 'picked up', 'delivered', 'cancelled'],
        default: 'pending'
    },
    vendorId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Register',
        required: true
    },
    paymentDetails: {
        razorpay_payment_id: String,
        razorpay_order_id: String,
        razorpay_signature: String,
        paymentStatus: {
            type: String,
            enum: ['pending', 'completed', 'failed'],
            default: 'pending'
        }
    },
    vendorPayment: {
        status: {
            type: String,
            enum: ['pending', 'completed'],
            default: 'pending'
        },
        amount: Number,
        transferDate: Date
    }
}, {
    timestamps: true
});

const Order = mongoose.model('Order', orderSchema);

export default Order; 
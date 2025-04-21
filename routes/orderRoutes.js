import express from 'express';
import Order from '../models/orderSchema.js';

const router = express.Router();

// Get all orders
router.get('/api/orders', async (req, res) => {
    try {
        const orders = await Order.find()
            .populate('userId', 'name')
            .populate('vendorId', 'name')
            .sort({ createdAt: -1 });
        res.json(orders);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching orders', error: error.message });
    }
});

// Update order status
router.put('/api/orders/:orderId/status', async (req, res) => {
    try {
        const { orderId } = req.params;
        const { status } = req.body;

        const order = await Order.findById(orderId);
        if (!order) {
            return res.status(404).json({ message: 'Order not found' });
        }

        // Update order status
        order.status = status;

        // If order is delivered, update vendor payment status
        if (status === 'delivered' && order.vendorPayment.status === 'pending') {
            order.vendorPayment.status = 'completed';
            order.vendorPayment.amount = order.totalAmount;
            order.vendorPayment.transferDate = new Date();
        }

        await order.save();
        res.json({ message: 'Order status updated successfully', order });
    } catch (error) {
        res.status(500).json({ message: 'Error updating order status', error: error.message });
    }
});

// Get vendor's earnings
router.get('/api/vendors/:vendorId/earnings', async (req, res) => {
    try {
        const { vendorId } = req.params;
        const orders = await Order.find({
            vendorId,
            'vendorPayment.status': 'completed'
        }).sort({ 'vendorPayment.transferDate': -1 });

        const totalEarnings = orders.reduce((sum, order) => sum + order.vendorPayment.amount, 0);
        
        res.json({
            totalEarnings,
            orders: orders.map(order => ({
                orderId: order._id,
                amount: order.vendorPayment.amount,
                transferDate: order.vendorPayment.transferDate
            }))
        });
    } catch (error) {
        res.status(500).json({ message: 'Error fetching vendor earnings', error: error.message });
    }
});

export default router; 
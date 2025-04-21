import mongoose from "mongoose";
import bcrypt from "bcrypt";

const registerSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  username: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    enum: ['user', 'vendor', 'admin'],
    default: 'user'
  },
  phone: {
    type: String,
    required: true,
    validate: {
      validator: function(v) {
        return /^\d{10}$/.test(v);
      },
      message: props => `${props.value} is not a valid phone number! Please enter a 10-digit number.`
    }
  },
  address: {
    street: String,
    city: String,
    state: String,
    zipCode: String
  },
  // Vendor specific fields
  businessName: {
    type: String,
    required: function() {
      return this.role === 'vendor';
    },
    validate: {
      validator: function(v) {
        if (this.role === 'vendor') {
          return v && v.length > 0;
        }
        return true;
      },
      message: 'Business Name is required for vendor accounts'
    }
  },
  businessAddress: {
    type: String,
    required: function() {
      return this.role === 'vendor';
    },
    validate: {
      validator: function(v) {
        if (this.role === 'vendor') {
          return v && v.length > 0;
        }
        return true;
      },
      message: 'Business Address is required for vendor accounts'
    }
  },
  isActive: {
    type: Boolean,
    default: true
  },
  preferences: {
    emailNotifications: {
      type: Boolean,
      default: true
    },
    smsNotifications: {
      type: Boolean,
      default: false
    }
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, { timestamps: true, toJSON: { virtuals: true }, toObject: { virtuals: true } });

// Update the updatedAt field before saving
registerSchema.pre('save', function(next) {
  this.updatedAt = new Date();
  next();
});

// Hash password before saving
registerSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Method to compare password
registerSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

const Register = mongoose.model("Register", registerSchema, "registers");

export default Register;

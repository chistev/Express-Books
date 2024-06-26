import mongoose from 'mongoose';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs'; 
dotenv.config();

// Connect to MongoDB using mongoose
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch(error => console.error('Error connecting to MongoDB:', error));

// Define the User schema
const userSchema = new mongoose.Schema({
    fullName: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    selectedGenres: [String],
    passwordResetToken: String,
    passwordResetTokenExpires: Date,
    isAdmin: {
        type: Boolean,
        default: false
    },
    profilePhoto: {
        type: String,  // Path to the profile photo
    }
});

// Create the User model
const User = mongoose.model('User', userSchema);

export default User;
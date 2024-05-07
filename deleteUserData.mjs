import mongoose from 'mongoose';
import User from './models/User.mjs';
import dotenv from 'dotenv';
dotenv.config();

// Connect to MongoDB using mongoose
mongoose.connect(process.env.MONGODB_URI)
    .then(() => {
        console.log('Connected to MongoDB');

        // Delete all documents from the User collection
        User.deleteMany({})
            .then(() => {
                console.log('All documents deleted from the User collection');
                // Optionally, you can close the connection after the operation is complete
                mongoose.connection.close();
            })
            .catch(error => {
                console.error('Error deleting documents:', error);
                // Close the connection on error as well
                mongoose.connection.close();
            });
    })
    .catch(error => {
        console.error('Error connecting to MongoDB:', error);
    });

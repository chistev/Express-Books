import mongoose from 'mongoose';
import Book from './models/Book.mjs';
import dotenv from 'dotenv';
dotenv.config();

// Connect to MongoDB using mongoose
mongoose.connect(process.env.MONGODB_URI)
    .then(() => {
        console.log('Connected to MongoDB');

        // Delete all documents from the Book collection
        Book.deleteMany({})
            .then(() => {
                console.log('All documents deleted from the Book collection');
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
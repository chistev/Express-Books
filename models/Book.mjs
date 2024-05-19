import mongoose from 'mongoose';

// Define the Book schema
const bookSchema = new mongoose.Schema({
    image: {
        type: String,
        required: true
    },
    title: {
        type: String,
        required: true
    },
    author: {
        type: String,
        required: true
    },
    rating: {
        type: Number,
        required: true,
        min: 1.0,
        max: 5.0
    },
    description: {
        type: String,
        required: true
    }
});

// Create the Book model
const Book = mongoose.model('Book', bookSchema);

export default Book;
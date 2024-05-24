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
    },
    genre: {
        type: [String],
        enum: ["Art", "Classics", "Contemporary", "Crime", "Fiction", "Historical Fiction", "History", "Humor and Comedy", "Nonfiction", "Religion", "Science", "Thriller"],
        required: true
    },
    pages: {
        type: Number,
        required: true
    },
    mediaType: {
        type: String,
        enum: ["Hardcover", "Paperback", "eBook", "Audiobook"],
        required: true
    }
});

// Create the Book model
const Book = mongoose.model('Book', bookSchema);

export default Book;
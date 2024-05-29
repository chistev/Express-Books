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
    },
    publishedDate: {
        type: Date,
        required: true
    },
    reviews: [{
        content: {
            type: String,
            required: true
        },
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: true
        },
        createdAt: {
            type: Date,
            default: Date.now
        },
        likes: [{
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        }]
    }]
});

// Create the Book model
const Book = mongoose.model('Book', bookSchema);

export default Book;
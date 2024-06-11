import express from 'express';
import Book from '../../models/Book.mjs';
import User from '../../models/User.mjs';
import { attachCSRFToken, verifyCSRFToken } from '../signinAndSignupControllers/csrfUtils.mjs';
import { determineLoggedInStatus } from '../signinAndSignupControllers/determineLoggedInStatus.mjs';
import mongoose from 'mongoose';

const router = express.Router();
router.use(attachCSRFToken);

router.get('/mybooks', async (req, res) => {
    const { loggedIn, userId } = determineLoggedInStatus(req);
    const csrfToken = req.csrfToken;

    const user = await User.findById(userId);
    const userName = user.fullName

    const searchQuery = req.query.search || '';

    const reviewedBooks = await Book.find({
        'reviews.user': new mongoose.Types.ObjectId(userId),
        $or: [
            // the $options: 'i' flag makes the search case-insensitive.
            { title: { $regex: searchQuery, $options: 'i' } }, 
            { author: { $regex: searchQuery, $options: 'i' } },
            { 'reviews.content': { $regex: searchQuery, $options: 'i' } }
        ]
    });

    const booksWithUserReviews = reviewedBooks.map(book => {
        const userReview = book.reviews.find(review => review.user.equals(userId));
        return {
            ...book.toObject(),
            userReview: userReview ? {
                _id: userReview._id,
                fullContent: userReview.content,
                truncatedContent: userReview.content.length > 200 ? userReview.content.slice(0, 200) + '...' : userReview.content
            } : null
        };
    });

    res.render('mybooks', { 
        title: `${userName}'s books on Myreads`,
        content: '', 
        csrfToken: csrfToken, 
        loggedIn, 
        isOwner: true,
        books: booksWithUserReviews, 
        searchQuery: searchQuery
    });
});

router.get('/book/:bookId/review/:reviewId', async (req, res) => {
    try {
        const bookId = req.params.bookId;
        const reviewId = req.params.reviewId;

        const book = await Book.findById(bookId);
        if (!book) {
            return res.status(404).json({ error: 'Book not found' });
        }

        const review = book.reviews.find(review => review._id.equals(reviewId));
        if (!review) {
            return res.status(404).json({ error: 'Review not found' });
        }

        res.json({ content: review.content });
    } catch (error) {
        console.error('Error fetching review:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

router.delete('/book/:bookId/review/:reviewId', verifyCSRFToken, async (req, res) => {
    const { bookId, reviewId } = req.params;
    const { userId } = determineLoggedInStatus(req);

    try {
        const book = await Book.findOneAndUpdate(
            { _id: bookId, 'reviews._id': reviewId, 'reviews.user': userId },
            { $pull: { reviews: { _id: reviewId } } },
            { new: true }
        );

        if (!book) {
            return res.status(404).json({ message: 'Book or review not found' });
        }

        res.json({ message: 'Review deleted successfully', book });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

export default router;
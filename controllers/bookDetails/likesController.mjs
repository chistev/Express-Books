import express from 'express';
import Book from '../../models/Book.mjs';
import { determineLoggedInStatus } from '../signinAndSignupControllers/determineLoggedInStatus.mjs'
import { attachCSRFToken, verifyCSRFToken } from '../signinAndSignupControllers/csrfUtils.mjs'
import bodyParser from 'body-parser';

const router = express.Router();

router.use(attachCSRFToken);
router.use(bodyParser.json());

router.post('/book/:bookId/review/:reviewId/like', verifyCSRFToken, async (req, res) => {
    console.log("router reached")
    try {
        const { bookId, reviewId } = req.params;
        const { loggedIn, userId } = determineLoggedInStatus(req);

        if (!loggedIn) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const book = await Book.findById(bookId);
        if (!book) {
            return res.status(404).json({ error: 'Book not found' });
        }

        const review = book.reviews.id(reviewId);
        if (!review) {
            return res.status(404).json({ error: 'Review not found' });
        }

        review.likes = review.likes.filter(like => like.user);

        const existingLike = review.likes.find(like => like.user.toString() === userId.toString());

        if (existingLike) {
            // If the user has already liked the review, remove the like (unlike)
            review.likes = review.likes.filter(like => like.user.toString() !== userId.toString());
        } else {
            // If the user has not liked the review yet, add the like
            review.likes.push({ user: userId, likedAt: new Date() });
        }

        await book.save();
        res.json({ likes: review.likes.length, liked: !existingLike });
    } catch (error) {
        console.error('Error liking review:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

export default router
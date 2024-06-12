import express from 'express';
import Book from '../../models/Book.mjs';
import { determineLoggedInStatus } from '../signinAndSignupControllers/determineLoggedInStatus.mjs'
import { attachCSRFToken, verifyCSRFToken } from '../signinAndSignupControllers/csrfUtils.mjs'
import addUserToLocals from '../authmiddleware.mjs'
import mongoose from 'mongoose';

const router = express.Router();

router.use(attachCSRFToken);
router.use(addUserToLocals);

router.get('/write_review/:bookId', async (req, res) => {
    const { loggedIn, userId } = determineLoggedInStatus(req);
    const errors = req.query.errors ? JSON.parse(req.query.errors) : [];
    const csrfToken = req.csrfToken;

    if (!loggedIn) {
        return res.redirect('/signin');
    }

    try {
        const book = await Book.findById(req.params.bookId);
        if (!book) {
            return res.status(404).send('Book not found');
        }

        console.log('User ID:', userId);

        // Find the user's review for this book
        let userReview = null;
        if (userId) {
            userReview = userId ? book.reviews.find(review => review.user && review.user.toString() === userId.toString()) : null;
        }

        res.render('write_review', { title: "Review", errors: errors, csrfToken: csrfToken, loggedIn, book, content: '', review: userReview ? userReview.content : '', bookId: req.params.bookId,    });
    } catch (error) {
        console.error('Error fetching book details for review:', error);
        res.status(500).send('Internal Server Error');
    }
});

router.post('/save_review_content/:bookId', verifyCSRFToken, async (req, res) => {
    try {
        const bookId = req.params.bookId;
        let content = req.body.content;

        const { loggedIn, userId } = determineLoggedInStatus(req);

        if (!loggedIn) {
            return res.redirect('/signin');
        }

        if (!mongoose.Types.ObjectId.isValid(bookId)) {
            return res.status(400).json({ error: 'Invalid book ID' });
        }

        const book = await Book.findById(bookId);
        if (!book) {
            return res.status(404).json({ error: 'Book not found' });
        }

        const activeReviews = book.reviews.filter(review => {
            return review.user && review.user.toString() !== userId.toString();
        });

        let userReview = activeReviews.find(review => {
            return review.user.toString() === userId.toString();
        });

        if (userReview) {
            userReview.content = content;
        } else {
            activeReviews.push({ content: content, user: new mongoose.Types.ObjectId(userId) });
        }

        book.reviews = activeReviews;

        await book.save();

        res.redirect(`/book/${bookId}/details`);
    } catch (error) {
        console.error('Error saving review content:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

export default router

import express from 'express';
import Book from '../../models/Book.mjs';
import User from '../../models/User.mjs';
import { determineLoggedInStatus } from '../signinAndSignupControllers/determineLoggedInStatus.mjs'
import { attachCSRFToken, verifyCSRFToken } from '../signinAndSignupControllers/csrfUtils.mjs'
import addUserToLocals from '../authmiddleware.mjs'
import bodyParser from 'body-parser';
import sanitizeHtml from 'sanitize-html';

const router = express.Router();

router.use(attachCSRFToken);
router.use(addUserToLocals);
router.use(bodyParser.json());

router.get('/comment/:commentId', async (req, res) => {
    try {
        const { commentId } = req.params;
        const book = await Book.findOne({ 'reviews.comments._id': commentId }, { 'reviews.$': 1 });

        if (!book) {
            return res.status(404).json({ success: false, error: 'Comment not found' });
        }

        const review = book.reviews[0];
        const comment = review.comments.id(commentId);

        if (!comment) {
            return res.status(404).json({ success: false, error: 'Comment not found' });
        }

        res.json({ success: true, content: comment.content });
    } catch (error) {
        console.error('Error fetching comment:', error);
        res.status(500).json({ success: false, error: 'Internal Server Error' });
    }
});

router.post('/book/:reviewId/comment', verifyCSRFToken, async (req, res) => {
    try {
        const { content } = req.body;
        const { loggedIn, userId } = determineLoggedInStatus(req);

        console.log('User logged in:', loggedIn);
        console.log('User ID:', userId);
        console.log('Request body:', req.body); // Add this line to log the request body

        if (!loggedIn || !userId) {
            console.log('User not logged in or userId not found.');
            return res.status(401).json({ success: false, error: 'User not logged in' });
        }

        // Fetch the user from the database
        const user = await User.findById(userId);
        console.log('User found:', user);
        if (!user) {
            console.log('User not found.');
            return res.status(404).json({ success: false, error: 'User not found' });
        }

        const book = await Book.findOne({ 'reviews._id': req.params.reviewId });
        console.log('Book found:', book);
        if (!book) {
            console.log('Book not found.');
            return res.status(404).json({ success: false, error: 'Book not found' });
        }

        const review = book.reviews.id(req.params.reviewId);

        if (typeof content !== 'string') {
            console.log('Invalid content type:', typeof content);
            return res.status(400).json({ success: false, error: 'Invalid content type' });
        }

        const trimmedContent = content.trim();

        if (!trimmedContent) {
            console.log('Comment content is empty.');
            return res.status(400).json({ success: false, error: 'Comment content cannot be empty' });
        }

        // Sanitize content to prevent XSS
        const sanitizedContent = sanitizeHtml(trimmedContent, {
            allowedTags: ['p', 'br', 'i', 'b', 'u'], // Allow only paragraph and line break tags
            allowedAttributes: {}
        });

        // Replace newlines with paragraph tags
        const formattedContent = sanitizedContent.split('\n').map(line => `<p>${line}</p>`).join('');

        // Push the comment with the user field properly set
        review.comments.push({ content: formattedContent, user: user._id });

        console.log('Comment added to review:', review.comments);

        await book.save();

        const formattedDate = new Date().toLocaleString('default', { month: 'long', day: 'numeric', year: 'numeric' });

        res.json({ success: true, comment: { content: formattedContent, userFullName: user.fullName, formattedDate } });
    } catch (error) {
        console.error('Error submitting comment:', error);
        res.status(500).json({ success: false, error: 'Internal Server Error' });
    }
});



router.delete('/comment/:commentId', verifyCSRFToken, async (req, res) => {
    try {
        const { commentId } = req.params;
        const { loggedIn, userId } = determineLoggedInStatus(req);

        if (!loggedIn || !userId) {
            return res.status(401).json({ success: false, error: 'User not logged in' });
        }

        const book = await Book.findOne({ 'reviews.comments._id': commentId });

        if (!book) {
            return res.status(404).json({ success: false, error: 'Comment not found' });
        }

        const review = book.reviews.find(review => review.comments.id(commentId));
        const comment = review.comments.id(commentId);

        if (comment.user.toString() !== userId.toString()) {
            return res.status(403).json({ success: false, error: 'User not authorized to delete this comment' });
        }

        review.comments.pull(commentId);
        await book.save();

        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting comment:', error);
        res.status(500).json({ success: false, error: 'Internal Server Error' });
    }
});

export default router

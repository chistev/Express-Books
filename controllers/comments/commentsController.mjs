import express from 'express';
import User from '../../models/User.mjs';
import Book from '../../models/Book.mjs';
import { attachCSRFToken, verifyCSRFToken } from '../signinAndSignupControllers/csrfUtils.mjs';
import { determineLoggedInStatus } from '../signinAndSignupControllers/determineLoggedInStatus.mjs';
import formatDate from '../dateUtils.mjs';
import bodyParser from 'body-parser';

const router = express.Router();
router.use(bodyParser.json());
router.use(attachCSRFToken);

router.get('/list', async (req, res) => {
    try {
        const { loggedIn, userId } = determineLoggedInStatus(req);

        console.log('User ID:', userId); // Log the userId obtained from determineLoggedInStatus

        if (!loggedIn) {
            return res.redirect('/signin');
        }

        const user = await User.findById(userId).select('fullName');

        if (!user) {
            return res.status(404).send('User not found');
        }

        const firstName = user.fullName.split(' ')[0];

        // Fetch books where the user has commented
        const userComments = await Book.find({ 'reviews.comments.user': userId })
            .populate({
                path: 'reviews.user',
                select: 'fullName'
            })
            .populate({
                path: 'reviews.comments.user',
                select: 'fullName'
            });

        // Process fetched comments
        const reviewsWithUserComments = userComments.flatMap(book => {
            return book.reviews.map(review => {
                const userComment = review.comments.find(comment => comment.user._id.equals(userId));
                if (userComment) {
                    return {
                        bookTitle: book.title,
                        reviewContent: review.content,
                        commenterName: userComment.user.fullName,
                        commenterId: userComment.user._id.toString(), // Convert ObjectId to string
                        commentCreatedAt: formatDate(userComment.createdAt),
                        reviewAuthorName: review.user.fullName,
                        reviewAuthorId: review.user._id.toString(), // Convert ObjectId to string
                        bookId: book._id.toString(), // Convert ObjectId to string
                        bookImage: book.image,
                        commentContent: userComment.content
                    };
                }
                return null;
            });
        }).filter(comment => comment !== null);

        console.log('User Comments:', reviewsWithUserComments); // Debugging log

        // Render comments page
        res.render('comments', {
            title: 'Your Comments',
            comments: reviewsWithUserComments,
            content: '',
            formatDate: formatDate,
            firstName: firstName
        });
    } catch (error) {
        console.error('Error fetching user comments:', error);
        res.status(500).send('Internal Server Error');
    }
});

router.post('/delete', verifyCSRFToken, async (req, res) => {
    try {
        const { loggedIn, userId } = determineLoggedInStatus(req);
        console.log("user id " + userId)

        if (!loggedIn) {
            return res.status(401).json({ success: false, message: 'You must be logged in to delete comments.' });
        }

        const { commenterId, bookId } = req.body;
        console.log("comment id " + commenterId)

        if (commenterId !== userId) {
            return res.status(403).json({ success: false, message: 'You are not authorized to delete this comment.' });
        }

        const book = await Book.findById(bookId);

        if (!book) {
            return res.status(404).json({ success: false, message: 'Book not found.' });
        }

        // Find the review with the comment to delete
        const review = book.reviews.find(review => review.comments.some(comment => comment.user.equals(commenterId)));

        if (!review) {
            return res.status(404).json({ success: false, message: 'Review not found.' });
        }

        // Find the index of the comment in the review
        const commentIndex = review.comments.findIndex(comment => comment.user.equals(commenterId));

        if (commentIndex === -1) {
            return res.status(404).json({ success: false, message: 'Comment not found.' });
        }

        // Remove the comment
        review.comments.splice(commentIndex, 1);
        await book.save();

        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting comment:', error);
        res.status(500).json({ success: false, message: 'Internal Server Error.' });
    }
});

export default router;

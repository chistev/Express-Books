import express from 'express';
import User from '../../models/User.mjs';
import Book from '../../models/Book.mjs';
import { attachCSRFToken, verifyCSRFToken } from '../signinAndSignupControllers/csrfUtils.mjs';
import { determineLoggedInStatus } from '../signinAndSignupControllers/determineLoggedInStatus.mjs';
import formatDate from '../dateUtils.mjs'

const router = express.Router();
router.use(attachCSRFToken);

router.get('/list', async (req, res) => {
    try {
        const { loggedIn, userId } = determineLoggedInStatus(req);

        if (!loggedIn) {
            return res.redirect('/signin');
        }

        const user = await User.findById(userId).select('fullName');

        if (!user) {
            return res.status(404).send('User not found');
        }

        const firstName = user.fullName.split(' ')[0];

        const userComments = await Book.find({ 'reviews.comments.user': userId })
            .populate({
                path: 'reviews.user',
                select: 'fullName'
            })
            .populate({
                path: 'reviews.comments.user',
                select: 'fullName'
            });

        const reviewsWithUserComments = userComments.flatMap(book => {
            return book.reviews.map(review => {
                const userComment = review.comments.find(comment => comment.user._id.equals(userId));
                if (userComment) {
                    return {
                        bookTitle: book.title,
                        reviewContent: review.content,
                        commenterName: userComment.user.fullName,
                        commenterId: userComment.user._id,
                        commentCreatedAt: formatDate(userComment.createdAt),
                        reviewAuthorName: review.user.fullName,
                        reviewAuthorId: review.user._id,
                        bookId: book._id,
                        bookImage: book.image,
                        commentContent: userComment.content
                    };
                }
                return null;
            });
        }).filter(comment => comment !== null);

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

        if (!loggedIn) {
            return res.status(401).json({ success: false, message: 'You must be logged in to delete comments.' });
        }

        const { commenterId, bookId } = req.body;

        if (commenterId !== userId) {
            return res.status(403).json({ success: false, message: 'You are not authorized to delete this comment.' });
        }

        const book = await Book.findById(bookId);

        if (book) {
            for (let review of book.reviews) {
                const commentIndex = review.comments.findIndex(comment => comment.user.equals(commenterId));

                if (commentIndex > -1) {
                    review.comments.splice(commentIndex, 1);
                    await book.save();
                    return res.json({ success: true });
                }
            }
        }

        res.json({ success: false });
    } catch (error) {
        console.error('Error deleting comment:', error);
        res.status(500).json({ success: false });
    }
});

export default router;

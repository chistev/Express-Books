import express from 'express';
import User from '../../models/User.mjs';
import Book from '../../models/Book.mjs';
import { attachCSRFToken } from '../signinAndSignupControllers/csrfUtils.mjs';
import { determineLoggedInStatus } from '../signinAndSignupControllers/determineLoggedInStatus.mjs';
import formatDate from '../dateUtils.mjs';

const router = express.Router();
router.use(attachCSRFToken);

router.get('/', async (req, res) => {
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

        const booksWithLikedReviews = await Book.find({ 'reviews.likes.user': userId })
            .populate({
                path: 'reviews.user', 
                select: 'fullName'
            });

        const likedReviews = booksWithLikedReviews.map(book => {
            return book.reviews.filter(review => review.likes.some(like => like.user.equals(userId))).map(review => {
                const like = review.likes.find(like => like.user.equals(userId));
                return {
                    bookTitle: book.title,
                    reviewContent: review.content,
                    reviewAuthorName: review.user.fullName, 
                    reviewAuthorId: review.user._id, 
                    bookId: book._id,
                    bookImage: book.image,
                    likeCreatedAt: like.likedAt
                };
            });
        }).flat();

        res.render('likes', {
            title: 'Your Likes',
            likes: likedReviews,
            content: '',
            formatDate: formatDate, 
            firstName: firstName, 
            userId: userId
        });
    } catch (error) {
        console.error('Error fetching user likes:', error);
        res.status(500).send('Internal Server Error');
    }
});

export default router;
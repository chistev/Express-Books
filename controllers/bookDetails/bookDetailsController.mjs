import express from 'express';
import Book from '../../models/Book.mjs';
import moment from 'moment';
import { determineLoggedInStatus } from '../signinAndSignupControllers/determineLoggedInStatus.mjs'
import { attachCSRFToken, verifyCSRFToken } from '../signinAndSignupControllers/csrfUtils.mjs'
import addUserToLocals from '../../controllers/authmiddleware.mjs'

const router = express.Router();

router.use(attachCSRFToken);
router.use(addUserToLocals);

router.get('/book/:id/details', async (req, res) => {
    try {
        const { loggedIn, userId } = determineLoggedInStatus(req);
        const userIdStr = userId ? userId.toString() : null;

        const book = await Book.findById(req.params.id)
            .populate('reviews.user', 'fullName')
            .populate('reviews.comments.user', 'fullName');

        if (!book) {
            return res.status(404).send('Book not found');
        }

        const userIds = book.reviews
            .filter(review => review.user)
            .map(review => review.user._id);
    
        const userReviewCounts = await Book.aggregate([
            { $unwind: '$reviews' },
            { $match: { 'reviews.user': { $in: userIds } } },
            { $group: { _id: '$reviews.user', count: { $sum: 1 } } }
        ]);

        const reviewCountsMap = userReviewCounts.reduce((map, userReview) => {
            map[userReview._id.toString()] = userReview.count;
            return map;
        }, {});

        const reviewsWithFormattedDate = book.reviews.map(review => {
            const formattedDate = moment(review.createdAt).format('MMMM D, YYYY');

            const filteredLikes = review.likes.filter(like => like !== null);

            const likedByUser = review.likes.some(like => like.user && like.user.equals(userId));
            console.log(`Review ID: ${review._id}, Likes: ${filteredLikes.length}, Liked by User: ${likedByUser}`);

            const commentsWithFormattedDate = review.comments
                .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))
                .map(comment => ({
                    ...comment._doc,
                    formattedDate: moment(comment.createdAt).format('MMMM D, YYYY'),
                    user: comment.user || { fullName: 'Anonymous' }
                }));

            return {
                ...review._doc,
                formattedDate: formattedDate,
                truncatedContent: review.content.length > 200 ? review.content.slice(0, 200) + '...' : review.content,
                likedByUser: likedByUser,
                comments: commentsWithFormattedDate,
                commentCount: review.comments.length, 
                userReviewCount: review.user ? reviewCountsMap[review.user._id.toString()] || 0 : 0,
                user: review.user || { fullName: 'Anonymous' }
            };
        });

        console.log('Book with formatted review dates:', { ...book._doc, reviews: reviewsWithFormattedDate });

        const truncatedDescription = book.description.split(' ').slice(0, 50).join(' ') + (book.description.split(' ').length > 50 ? ' ...' : '');

        console.log('Final reviews sent to template:', reviewsWithFormattedDate);


        res.render('bookDetails/book_details', { 
            title: book.title, 
            book: { ...book._doc, description: truncatedDescription, reviews: reviewsWithFormattedDate },  
            content: "", 
            loggedIn, 
            reviews: reviewsWithFormattedDate,
            userId: userIdStr,
            reviewCount: book.reviews.length,
            
        });
    } catch (error) {
        console.error('Error fetching book details:', error);
        res.status(500).send('Internal Server Error');
    }
});

export default router;
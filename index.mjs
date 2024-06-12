import express from 'express';
import session from 'express-session';
import dotenv from 'dotenv';
import registerController from './controllers/signinAndSignupControllers/registerController.mjs'
import otpRequestController from './controllers/signinAndSignupControllers/otpRequestController.mjs'
import otpResendController from './controllers/signinAndSignupControllers/otpResendController.mjs'
import favoriteGenreController from './controllers/signinAndSignupControllers/favoriteGenreController.mjs'
import User from './models/User.mjs';
import { attachCSRFToken, verifyCSRFToken } from './controllers/signinAndSignupControllers/csrfUtils.mjs';
import bcrypt from 'bcryptjs'; 
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import { determineLoggedInStatus } from './controllers/signinAndSignupControllers/determineLoggedInStatus.mjs'
import signinWithEmailController from './controllers/signinAndSignupControllers/signInWithEmailController.mjs'
import forgotPasswordController from './controllers/signinAndSignupControllers/forgotPasswordController.mjs'
import passwordResetController from './controllers/signinAndSignupControllers/passwordResetController.mjs'
import multer from 'multer';
import Book from './models/Book.mjs';
import Genre from './models/Genre.mjs';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import _ from 'lodash';
import sanitizeHtml from 'sanitize-html';
import { JSDOM } from 'jsdom';
import createDOMPurify from 'dompurify';
import mongoose from 'mongoose';
import bodyParser from 'body-parser';
import { body, validationResult } from 'express-validator';
import moment from 'moment';
import addUserToLocals from './controllers/authmiddleware.mjs'
import accountSettingsRouter from './controllers/accountSettings/accountSettingsController.mjs'
import addBookController from './controllers/admin/addBookController.mjs';
import bookDetailsController from './controllers/bookDetails/bookDetailsController.mjs';
import changePasswordController from './controllers/accountSettings/changePasswordController.mjs'
import commentsController from './controllers/comments/commentsController.mjs'
import deleteAccountController from './controllers/accountSettings/deleteAccountController.mjs'
import deleteBookController from './controllers/admin/deleteBookController.mjs';
import editBookController from './controllers/admin/editBookController.mjs'
import editFavoriteGenreController from './controllers/editFavoriteGenre/editFavoriteGenre.mjs'
import editGenreController from './controllers/admin/editGenreController.mjs'
import likesController from './controllers/likes/likesController.mjs'
import myBooksController from './controllers/myBooks/myBooksController.mjs'
import writeReviewController from './controllers/writeReview/writeReviewController.mjs'

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

dotenv.config();
const app = express();
const port = 3000;

// Configure express-session middleware
app.use(session({
    secret: process.env.SECRET, 
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Set to true if using HTTPS
        maxAge: null // Session cookie by default
    }
}));

// Use express.static middleware to serve static files
app.use(express.static('public'));

// Set EJS as the view engine
app.set('view engine', 'ejs');

// Middleware to parse URL-encoded form data
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Use cookie-parser middleware
app.use(cookieParser());

app.use('/register', registerController);
app.use('/otp-request', otpRequestController);
app.use('/resend-otp', otpResendController);
app.use('/favorite-genre', favoriteGenreController);
app.use('/favorite-genre', favoriteGenreController);
app.use('/signin_with_email', signinWithEmailController);
app.use('/forgot_password', forgotPasswordController)
app.use('/password_reset', passwordResetController)
app.use('/', addBookController);
app.use('/', bookDetailsController);
app.use('/', changePasswordController);
app.use('/comments', commentsController);
app.use('/delete_account', deleteAccountController)
app.use('/', deleteBookController)
app.use('/', editBookController)
app.use('/edit_favorite_genre', editFavoriteGenreController);
app.use('/', editGenreController)
app.use('/likes/list', likesController)
app.use('/', myBooksController)
app.use('/', writeReviewController)

// Middleware to parse JSON bodies
app.use(bodyParser.json());
// Add middleware to add user to locals
app.use(addUserToLocals);

app.get('/', async (req, res) => {
    try {
        const { loggedIn, userId } = determineLoggedInStatus(req);

        if (!loggedIn) {
            return res.redirect('/new_releases');
        }

        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).send('User not found');
        }

        const selectedGenresLower = user.selectedGenres.map(genre => genre.toLowerCase());

        const books = await Book.find().lean(); // lean() to get plain JavaScript objects
        const filteredBooks = books.filter(book => {
            const bookGenresLower = book.genre.map(genre => genre.toLowerCase());
            return bookGenresLower.some(genre => selectedGenresLower.includes(genre));
        });

        console.log('Books to be rendered:', filteredBooks);

        res.render('index', { 
            title: 'Free Online Books', 
            loggedIn, 
            books: filteredBooks, 
            isSearchResult: false, 
            currentPage: 1, 
            totalPages: 1.,
            content:''
        });
    } catch (error) {
        console.error('Error fetching books:', error);
        res.status(500).send('Error fetching books');
    }
});

app.post('/logout', (req, res) => {
    // Clear the token cookie
    res.clearCookie('token');
    // Redirect the user to the sign-in page
    res.redirect('/');
});

app.get('/logout', (req, res) => {
    // Clear the token cookie
    res.clearCookie('token');
    // Redirect the user to the sign-in page
    res.redirect('/');
});

app.get('/signup', (req, res) => {
    res.render('registration/signup', { title: 'Sign Up', message: 'Sign up for MyReads!' });
});

app.get('/signin', (req, res) => {
    res.render('signin/signin', { title: 'Sign in', content: ''});
});

app.get('/terms_of_service', (req, res) => {
    const loggedIn = determineLoggedInStatus(req);
    res.render('terms_of_service', { title: 'Terms of Use | Myreads', content: '', loggedIn });
});

app.get('/privacy_policy', (req, res) => {
    const loggedIn = determineLoggedInStatus(req);
    res.render('Privacy_policy', { title: 'Privacy Policy | Myreads', content: '', loggedIn });
});

app.get('/new_releases', async (req, res) => {
    const { loggedIn } = determineLoggedInStatus(req);
    const page = parseInt(req.query.page) || 1;
    const limit = 10; // Number of books per page
    const skip = (page - 1) * limit;

    try {
        const totalBooks = await Book.countDocuments();
        const books = await Book.find().sort({ createdAt: -1 }).skip(skip).limit(limit);

        books.forEach(book => {
            const words = book.description.split(' ');
            // Take the first 40 words and join them back into a string
            book.description = words.slice(0, 40).join(' ');
            if (words.length > 40) {
                book.description += ' ...';
            }
        });

        res.render('new_releases', { title: 'New Releases', loggedIn, content: '', books, currentPage: page, 
        totalPages: Math.ceil(totalBooks / limit), isSearchResult: false });
    } catch (error) {
        console.error('Error fetching books:', error);
        res.status(500).send('Internal Server Error');
    }
});

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

app.get('/book/:id', async (req, res) => {
    try {
        // Fetch the book from the database by ID
        const book = await Book.findById(req.params.id);
        if (!book) {
            return res.status(404).send('Book not found');
        }

         // Sanitize the description
         const sanitizedDescription = DOMPurify.sanitize(book.description);

         // Send the sanitized description as a response
        res.json({ description: sanitizedDescription });
    } catch (error) {
        console.error('Error fetching book:', error);
        res.status(500).send('Internal Server Error');
    }
});


app.delete('/comment/:commentId', async (req, res) => {
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

app.get('/comment/:commentId', async (req, res) => {
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


app.post('/book/:reviewId/comment', async (req, res) => {
    try {
        const { content } = req.body;
        const { loggedIn, userId } = determineLoggedInStatus(req);

        console.log('User logged in:', loggedIn);
        console.log('User ID:', userId);

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

app.post('/book/:bookId/review/:reviewId/like', async (req, res) => {
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

        // Ensure likes array contains valid entries and remove null values
        review.likes = review.likes.filter(like => like.user);

        // Check if the current user has already liked the review
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

app.get('/genre/:genre', async (req, res) => {
    const { genre } = req.params;

    try {
        const { loggedIn } = determineLoggedInStatus(req);
        const books = await Book.find({ genre });

        const genreDescription = await Genre.findOne({ name: genre });

        const allGenres = await Genre.find({});

        res.render('category', { 
            title: genre.charAt(0).toUpperCase() + genre.slice(1),
            description: genreDescription ? genreDescription.description : 'No description available.',
            content: '', 
            loggedIn, 
            books,
            allGenres 
        });
    } catch (error) {
        console.error('Error fetching books by genre:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/user/:userId', async (req, res) => {
    const { loggedIn } = determineLoggedInStatus(req);
    const userId = req.params.userId;
    const errors = req.query.errors ? JSON.parse(req.query.errors) : [];
    const csrfToken = req.csrfToken;

    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).send('User not found');
        }

        // Calculate the total number of reviews made by the user
        const totalReviews = await Book.countDocuments({ 'reviews.user': userId });

        res.render('user', { 
            title: 'User Profile', 
            user, 
            totalReviews, // Pass the total number of reviews to the view
            errors: errors, 
            content: '', 
            csrfToken: csrfToken, 
            loggedIn, 
            book: ''
        });
    } catch (error) {
        console.error('Error fetching user profile:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/user/:userId/mybooks', async (req, res) => {
    const { loggedIn, userId } = determineLoggedInStatus(req);
    const targetUserId = req.params.userId;

    // Default value for isOwner
    let isOwner = false;

    if (userId === targetUserId) {
        // Update isOwner if the user is the owner
        isOwner = true;
        res.redirect('/mybooks');
    } else {
        const errors = req.query.errors ? JSON.parse(req.query.errors) : [];
        const csrfToken = req.csrfToken;
        
        const searchQuery = req.query.search || '';
        
        const targetUser = await User.findById(targetUserId);
        if (!targetUser) {
            return res.status(404).send('User not found');
        }
        
        const reviewedBooks = await Book.find({
            'reviews.user': new mongoose.Types.ObjectId(targetUserId),
            $or: [
                { title: { $regex: searchQuery, $options: 'i' } },
                { author: { $regex: searchQuery, $options: 'i' } },
                { 'reviews.content': { $regex: searchQuery, $options: 'i' } }
            ]
        });
        
        // Extract the target user's review for each book and include the review ID
        const booksWithUserReviews = reviewedBooks.map(book => {
            const userReview = book.reviews.find(review => review.user.equals(targetUserId));
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
            title: `${targetUserId === userId ? 'Your' : targetUser.fullName + "'s"} books on Myreads`, 
            errors: errors, 
            content: '', 
            csrfToken: csrfToken, 
            loggedIn, 
            isOwner, // Pass the ownership flag to the template
            books: booksWithUserReviews, 
            searchQuery: searchQuery 
        });
    }
});

app.get('/search/json', async (req, res) => {
    const query = req.query.query || '';
    try {
        console.log(`Search query (AJAX): ${query}`);
        const books = await Book.find({
            $or: [
                { title: new RegExp(query, 'i') },
                { author: new RegExp(query, 'i') }
            ]
        }).limit(10);

        res.json(books);
    } catch (err) {
        console.error('Error fetching search results (AJAX):', err);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

app.get('/search', async (req, res) => {
    const query = req.query.query || '';
    try {
        const books = await Book.find({
            $or: [
                { title: new RegExp(query, 'i') },
                { author: new RegExp(query, 'i') }
            ]
        }).limit(10);

        res.render('new_releases', { 
            title: 'Search Results for: ' + query, 
            content: '',
            books,
            currentPage: 1, 
            totalPages: 1, // all results fit on one page
            isSearchResult: true,
            query
        });
    } catch (err) {
        console.error('Error fetching search results (Page):', err);
        res.status(500).send(err);
    }
});


app.get('/account_settings', (req, res) => {
    res.redirect('/account_settings/profile');
});

app.use('/account_settings', accountSettingsRouter);


// Start the server
app.listen(port, () => {
    console.log(`MyReads app listening at http://localhost:${port}`);
});
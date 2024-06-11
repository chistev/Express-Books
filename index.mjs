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

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

dotenv.config();
const app = express();
const port = 3000;

// Configure express-session middleware
app.use(session({
    secret: process.env.SECRET, 
    resave: false,
    saveUninitialized: true
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
// Middleware to parse JSON bodies
app.use(bodyParser.json());
// Add middleware to add user to locals
app.use(addUserToLocals);

// Route for the home page
app.get('/', async (req, res) => {
    // Determine the loggedIn status
    const { loggedIn } = determineLoggedInStatus(req);

    res.render('index', { title: 'Free Online Books', loggedIn, content: '' });
});

app.post('/logout', (req, res) => {
    // Clear the token cookie
    res.clearCookie('token');
    // Redirect the user to the sign-in page
    res.redirect('/');
});

app.get('/myreads', (req, res) => {
    res.redirect('/');
});

app.get('/signup', (req, res) => {
    res.render('signup', { title: 'Sign Up', message: 'Sign up for MyReads!' });
});

app.get('/signin', (req, res) => {
    res.render('signin', { title: 'Sign in', content: ''});
});

app.get('/password_reset_email_sent', attachCSRFToken, (req, res) => {
    const csrfToken = req.csrfToken;
    res.render('password_reset_email_sent', { title: 'Myreads Password Assistance', content: '', csrfToken: csrfToken });
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
    // Determine the loggedIn status
    const { loggedIn } = determineLoggedInStatus(req);
    const page = parseInt(req.query.page) || 1;
    const limit = 10; // Number of books per page
    const skip = (page - 1) * limit;

    try {
        const totalBooks = await Book.countDocuments();
        const books = await Book.find().sort({ createdAt: -1 }).skip(skip).limit(limit);

        // Modify the description of each book to include only the first 20 words
        books.forEach(book => {
            // Split the description into words
            const words = book.description.split(' ');
            // Take the first 20 words and join them back into a string
            book.description = words.slice(0, 20).join(' ');
            // Add "..." at the end
            if (words.length > 20) {
                book.description += ' ...';
            }
        });

        // Render the template with the books
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

// Route to get more comments for a specific review
app.get('/reviews/:reviewId/comments', async (req, res) => {
    try {
        const { reviewId } = req.params;
        const { offset } = req.query;

        // Fetch the review with the specified ID and populate the comments
        const review = await Book.findOne({ 'reviews._id': reviewId }, { 'reviews.$': 1 })
            .populate('reviews.comments.user', 'fullName')
            .lean();

        if (!review) {
            return res.status(404).send('Review not found');
        }

        const comments = review.reviews[0].comments
        .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))
            .slice(offset, offset + 5)
            .map(comment => ({
                ...comment,
                formattedDate: moment(comment.createdAt).format('MMMM D, YYYY'),
            }));

        res.json({ comments });
    } catch (error) {
        console.error('Error fetching more comments:', error);
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



app.get('/book/:bookId/review/:reviewId', async (req, res) => {
    try {
        const bookId = req.params.bookId;
        const reviewId = req.params.reviewId;

        // Find the book by ID
        const book = await Book.findById(bookId);
        if (!book) {
            return res.status(404).json({ error: 'Book not found' });
        }

        // Find the review within the book's reviews array
        const review = book.reviews.find(review => review._id.equals(reviewId));
        if (!review) {
            return res.status(404).json({ error: 'Review not found' });
        }

        // Return the review content
        res.json({ content: review.content });
    } catch (error) {
        console.error('Error fetching review:', error);
        res.status(500).json({ error: 'Internal Server Error' });
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

const isAdmin = (req, res, next) => {
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    try {
        const decoded = jwt.verify(token, process.env.SECRET);

        if (decoded && decoded.isAdmin) {
            next();
        } else {
            return res.status(403).json({ message: 'Forbidden' });
        }
    } catch (error) {
        console.error('Error verifying JWT token:', error);
        return res.status(500).json({ message: 'Internal Server Error' });
    }
};

app.post('/admin', verifyCSRFToken, async (req, res) => {
    const errors = [];
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email: email });
        if (user) { 
            if (user.password) { 
                const passwordMatch = await bcrypt.compare(password, user.password);
                if (!passwordMatch) {
                    errors.push("Your password is incorrect");
                    return res.redirect('/admin?errors=' + encodeURIComponent(JSON.stringify(errors)));
                }
                if (user.isAdmin) {
                    res.redirect('/admin/add_book');
                } else {
                    errors.push("User is not an admin");
                    return res.redirect('/admin?errors=' + encodeURIComponent(JSON.stringify(errors)));
                }
            } 
        } else {
            errors.push("User does not exist.");
            return res.redirect('/admin?errors=' + encodeURIComponent(JSON.stringify(errors)));
            }
        }
    catch (error) {
        errors.push("Error during sign in:", error);
        return res.redirect('/admin?errors=' + encodeURIComponent(JSON.stringify(errors)));
        }
});

// Set up multer for file upload
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});

const fileFilter = (req, file, cb) => {
    // Check if the file is an image
    if (!file.originalname.match(/\.(jpg|jpeg|png|gif)$/)) {
        return cb(new Error('Only image files are allowed!'), false);
    }
    cb(null, true);
};

const upload = multer({ 
    storage: storage,
    fileFilter: fileFilter
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

app.get('/mybooks', async (req, res) => {
    const { loggedIn, userId } = determineLoggedInStatus(req);
    const errors = req.query.errors ? JSON.parse(req.query.errors) : [];
    const csrfToken = req.csrfToken;

    const searchQuery = req.query.search || '';

    const reviewedBooks = await Book.find({
        'reviews.user': new mongoose.Types.ObjectId(userId),
        $or: [
            { title: { $regex: searchQuery, $options: 'i' } },
            { author: { $regex: searchQuery, $options: 'i' } },
            { 'reviews.content': { $regex: searchQuery, $options: 'i' } }
        ]
    });

    // Extract the user's review for each book and include the review ID
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
        title: "Stephen Owabie's books on Myreads", 
        errors: errors, 
        content: '', 
        csrfToken: csrfToken, 
        loggedIn, 
        isOwner: true, // Default value for isOwner
        books: booksWithUserReviews, 
        searchQuery: searchQuery
    });
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

app.delete('/book/:bookId/review/:reviewId', async (req, res) => {
    const { bookId, reviewId } = req.params;
    const { userId } = determineLoggedInStatus(req);

    try {
        // Find the book by ID and the review by ID, ensuring the review belongs to the user
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


app.get('/write_review/:bookId', async (req, res) => {
    const loggedIn = determineLoggedInStatus(req);
    const errors = req.query.errors ? JSON.parse(req.query.errors) : [];
    const csrfToken = req.csrfToken;

    try {
        const book = await Book.findById(req.params.bookId);
        if (!book) {
            return res.status(404).send('Book not found');
        }
        // Determine user logged in status and get the user ID
        const loggedInStatus = determineLoggedInStatus(req);
        const userId = loggedInStatus.loggedIn ? loggedInStatus.userId : null;
        
        console.log('User ID:', userId);

        // Find the user's review for this book
        let userReview = null;
        if (userId) {
            userReview = userId ? book.reviews.find(review => review.user && review.user.toString() === userId.toString()) : null;
        }

        res.render('write_review', { title: "Review", errors: errors, csrfToken: csrfToken, loggedIn, book, content: '', review: userReview ? userReview.content : '', bookId: req.params.bookId    });
    } catch (error) {
        console.error('Error fetching book details for review:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/save_review_content/:bookId', 
async (req, res) => {
    try {
        console.log("reading")
        const bookId = req.params.bookId;
        let content = req.body.content;

           // Log incoming data
           console.log(`Book ID: ${bookId}`);
           console.log(`Content: ${content}`);
           
         // Determine user logged in status and get the user ID
        const loggedInStatus = determineLoggedInStatus(req);
        const userId = loggedInStatus.loggedIn ? loggedInStatus.userId : null;
        
         console.log(userId + "this is it")

         // Check if bookId is a valid ObjectId
        if (!mongoose.Types.ObjectId.isValid(bookId)) {
            return res.status(400).json({ error: 'Invalid book ID' });
        }

        // Check if the user has already reviewed the book
        const book = await Book.findById(bookId);
        if (!book) {
            return res.status(404).json({ error: 'Book not found' });
        }

        let userReview = book.reviews.find(review => review.user && review.user.toString() === userId.toString());

        if (userReview) {
            // Update the existing review
            userReview.content = content;
        } else {
            // Add a new review
            book.reviews.push({ content: content, user:  new mongoose.Types.ObjectId(userId) });
        }

        await book.save();

        // Send a success response
        console.log('Review content saved successfully');
        res.status(200).json({ message: 'Review content saved successfully' });
    } catch (error) {
        console.error('Error saving review content:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/search', async (req, res) => {
    const query = req.query.query;
    try {
        const books = await Book.find({
            $or: [
                { title: new RegExp(query, 'i') },
                { author: new RegExp(query, 'i') }
            ]
        }).limit(10);

        // Determine the loggedIn status
        const { loggedIn } = determineLoggedInStatus(req);

        // Modify the description of each book to include only the first 20 words
        books.forEach(book => {
            const words = book.description.split(' ');
            book.description = words.slice(0, 20).join(' ');
            if (words.length > 20) {
                book.description += ' ...';
            }
        });

        
        // Render the new_releases template with the search results
        res.render('new_releases', { 
            title: 'Search Results for: ' + query, 
            loggedIn, 
            content: '',
            books,
            currentPage: 1, // Assuming it's the first page
            totalPages: 1, // Assuming all results fit on one page
            isSearchResult: true, // Flag to indicate it's a search result page
            query
        });
    } catch (err) {
        res.status(500).send(err);
    }
});


function formatDate(dateString) {
    const date = new Date(dateString);
    
    const options = {
        year: 'numeric',
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        hour12: true
    };
    const formattedDate = date.toLocaleDateString('en-US', options);
    return formattedDate;
}

app.get('/likes/list', async (req, res) => {
    try {
        // Determine user logged in status and get the user ID
        const { loggedIn, userId } = determineLoggedInStatus(req);

        if (!loggedIn) {
            return res.redirect('/login'); // Redirect to login if user not logged in
        }

        // Fetch user details to get the full name
        const user = await User.findById(userId).select('fullName');

        if (!user) {
            return res.status(404).send('User not found');
        }

        // Extract the first name from the full name
        const firstName = user.fullName.split(' ')[0];

        // Fetch books containing reviews liked by the current user
        const booksWithLikedReviews = await Book.find({ 'reviews.likes.user': userId })
            .populate({
                path: 'reviews.user', // Populate the user who authored the review
                select: 'fullName' // Select only the fullName field of the user who authored the review
            });

        // Extract review details for the liked reviews
        const likedReviews = booksWithLikedReviews.map(book => {
            return book.reviews.filter(review => review.likes.some(like => like.user.equals(userId))).map(review => {
                const like = review.likes.find(like => like.user.equals(userId));
                return {
                    bookTitle: book.title,
                    reviewContent: review.content,
                    reviewAuthorName: review.user.fullName, // Access the fullName of the user who authored the review
                    reviewAuthorId: review.user._id, // Access the ID of the user who authored the review
                    bookId: book._id,
                    bookImage: book.image,
                    likeCreatedAt: like.likedAt // Date when the like was placed
                };
            });
        }).flat(); // Flatten the array of arrays

        // Render the likes list page with the liked reviews
        res.render('likes', {
            title: 'Your Likes',
            likes: likedReviews,
            content: '',
            formatDate: formatDate, // Pass the formatDate function to the template
            firstName: firstName, // Pass the first name to the template
            userId: userId // Pass the userId to the template
        });
    } catch (error) {
        console.error('Error fetching user likes:', error);
        res.status(500).send('Internal Server Error');
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
import express from 'express';
import session from 'express-session';
import dotenv from 'dotenv';
import registerController from './controllers/signinAndSignupControllers/registerController.mjs'
import otpRequestController from './controllers/signinAndSignupControllers/otpRequestController.mjs'
import otpResendController from './controllers/signinAndSignupControllers/otpResendController.mjs'
import favoriteGenreController from './controllers/signinAndSignupControllers/favoriteGenreController.mjs'
import User from './models/User.mjs';
import cookieParser from 'cookie-parser';
import { determineLoggedInStatus } from './controllers/signinAndSignupControllers/determineLoggedInStatus.mjs'
import signinWithEmailController from './controllers/signinAndSignupControllers/signInWithEmailController.mjs'
import forgotPasswordController from './controllers/signinAndSignupControllers/forgotPasswordController.mjs'
import passwordResetController from './controllers/signinAndSignupControllers/passwordResetController.mjs'
import Book from './models/Book.mjs';
import Genre from './models/Genre.mjs';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import _ from 'lodash';
import { JSDOM } from 'jsdom';
import createDOMPurify from 'dompurify';
import mongoose from 'mongoose';
import bodyParser from 'body-parser';
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
import bookDetailscommentsController from './controllers/bookDetails/commentsController.mjs'
import bookDetailsLikesController from './controllers/bookDetails/likesController.mjs'
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import mongoSanitize from 'express-mongo-sanitize';
import compression from 'compression';
import connectMongoDBSession from 'connect-mongodb-session';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

dotenv.config();
const app = express();
const port = 3000;

// MongoDB session store
const MongoDBStore = connectMongoDBSession(session);

// MongoDB session store
const store = new MongoDBStore({
    uri: process.env.MONGODB_URI,
    collection: 'sessions',
    expires: 1000 * 60 * 60 * 24 * 30, // 30 days
    connectionOptions: {
      serverSelectionTimeoutMS: 10000
    }
  });

  // Logging for session store connection
store.on('connected', function() {
    console.log('Session store connected successfully');
  });

  store.on('error', function (error) {
    console.log('Session store error:', error);
  });

// Configure express-session middleware
app.use(session({
    secret: process.env.SECRET, 
    resave: false,
    saveUninitialized: true,
    store: store,
    cookie: {
        secure: process.env.NODE_ENV === 'true', // Set to true if using HTTPS, production if using http
        maxAge: 1000 * 60 * 60 * 24 * 30 // 30 days
    }
}));

// Additional logging for session data
app.use((req, res, next) => {
    console.log('Session Data:', req.session);
    next();
});

// Set the view engine to ejs
app.set('view engine', 'ejs');

// Use Compression middleware to gzip responses
app.use(compression());
  

// Configure rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again after 15 minutes'
});

app.use(limiter);

// Use express-mongo-sanitize to prevent NoSQL injection
app.use(mongoSanitize());


// centralized error handling mechanism.
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
  });
  

// Use express.static middleware to serve static files
app.use(express.static('public'));

// Set EJS as the view engine
app.use(express.static('public', {
    maxAge: '1y',
    etag: false,
  }));
  

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
app.use('/', bookDetailscommentsController)
app.use('/', bookDetailsLikesController)

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

        const page = parseInt(req.query.page) || 1;
        const limit = 10; // Number of books per page
        const skip = (page - 1) * limit;

        const allBooks = await Book.find().sort({ createdAt: -1 }).lean();
        const filteredBooks = allBooks.filter(book => {
            const bookGenresLower = book.genre.map(genre => genre.toLowerCase());
            return bookGenresLower.some(genre => selectedGenresLower.includes(genre));
        });

        const totalBooks = filteredBooks.length;
        const paginatedBooks = filteredBooks.slice(skip, skip + limit);

        // Truncate descriptions
        paginatedBooks.forEach(book => {
            const words = book.description.split(' ');
            book.description = words.slice(0, 40).join(' ');
            if (words.length > 40) {
                book.description += ' ...';
            }
        });

        console.log('Books to be rendered:', paginatedBooks);

        res.render('index', { 
            title: 'Free Online Books', 
            loggedIn, 
            books: paginatedBooks, 
            isSearchResult: false, 
            currentPage: page, 
            totalPages: Math.ceil(totalBooks / limit),
            content: ''
        });
    } catch (error) {
        console.error('Error fetching books:', error);
        res.status(500).send('Error fetching books');
    }
});

app.post('/logout', (req, res) => {
    // Destroy the session
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).send('Something went wrong while logging out.');
        }
        // Clear the token cookie
        res.clearCookie('token');
        res.clearCookie('connect.sid'); // Clear the session ID cookie
        res.redirect('/');
    });
});

app.get('/logout', (req, res) => {
    // Destroy the session
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).send('Something went wrong while logging out.');
        }
        // Clear the token cookie
        res.clearCookie('token');
        res.clearCookie('connect.sid'); // Clear the session ID cookie
        res.redirect('/');
    });
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
        const books = await Book.find().sort({ createdAt: -1 }).skip(skip).limit(limit).lean();

        books.forEach(book => {
            const words = book.description.split(' ');
            // Take the first 40 words and join them back into a string
            book.description = words.slice(0, 40).join(' ');
            if (words.length > 40) {
                book.description += ' ...';
            }
        });

        console.log('Books to be rendered (new releases):', books);

        res.render('new_releases', { 
            title: 'New Releases', 
            loggedIn, 
            content: '', 
            books, 
            currentPage: page, 
            totalPages: Math.ceil(totalBooks / limit), 
            isSearchResult: false 
        });
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
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
import accountSettingsRouter from './controllers/accountSettings/accountSettings.mjs'
import addBookController from './controllers/admin/addBookController.mjs';

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

// Middleware to parse JSON bodies
app.use(bodyParser.json());
// Add middleware to add user to locals
app.use(addUserToLocals);

// Attach CSRF token to all requests
app.use(attachCSRFToken);

// Verify CSRF token for all requests
app.use(verifyCSRFToken);
// Route for the home page
app.get('/', async (req, res) => {
    // Determine the loggedIn status
    const { loggedIn } = determineLoggedInStatus(req);

    res.render('index', { title: 'Free Online Books', loggedIn, content: '' });
});

// Add a route to handle logout
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

app.get('/book/:id/details', async (req, res) => {
    try {
        // Determine user logged in status and get the user ID
        const { loggedIn, userId } = determineLoggedInStatus(req);
        const userIdStr = userId ? userId.toString() : null;

        // Fetch the book from the database by ID and populate the user field in reviews and comments
        const book = await Book.findById(req.params.id)
            .populate('reviews.user', 'fullName')
            .populate('reviews.comments.user', 'fullName');

        if (!book) {
            return res.status(404).send('Book not found');
        }

        // Fetch the total number of reviews for each user
        const userIds = book.reviews
            .map(review => review.user ? review.user._id : null)
            .filter(id => id);  // Remove null values
        const userReviewCounts = await Book.aggregate([
            { $unwind: '$reviews' },
            { $match: { 'reviews.user': { $in: userIds } } },
            { $group: { _id: '$reviews.user', count: { $sum: 1 } } }
        ]);

        const reviewCountsMap = {};
        userReviewCounts.forEach(userReview => {
            reviewCountsMap[userReview._id.toString()] = userReview.count;
        });

        // Format the review dates and process likes array
        const reviewsWithFormattedDate = book.reviews.map(review => {
            const formattedDate = moment(review.createdAt).format('MMMM D, YYYY');

            const filteredLikes = review.likes.filter(like => like !== null);
            // Determine if the user has liked this review
            const likedByUser = review.likes.some(like => like.user && like.user.equals(userId));
            console.log(`Review ID: ${review._id}, Likes: ${filteredLikes.length}, Liked by User: ${likedByUser}`);

            // Format comment dates
            const commentsWithFormattedDate = review.comments
                .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))
                .map(comment => ({
                    ...comment._doc,
                    formattedDate: moment(comment.createdAt).format('MMMM D, YYYY'),
                    user: comment.user || { fullName: 'Anonymous' }  // Handle deleted user
                }));

            return {
                ...review._doc,
                formattedDate: formattedDate,
                truncatedContent: review.content.length > 200 ? review.content.slice(0, 200) + '...' : review.content,
                likedByUser: likedByUser,
                comments: commentsWithFormattedDate,
                commentCount: review.comments.length, // Include the total number of comments
                userReviewCount: review.user ? reviewCountsMap[review.user._id.toString()] || 0 : 0,  // Add total number of reviews for the user
                user: review.user || { fullName: 'Anonymous' }  // Handle deleted user
            };
        });

        // Check the book object to ensure reviews have formattedDate
        console.log('Book with formatted review dates:', { ...book._doc, reviews: reviewsWithFormattedDate });

        // Create a truncated version of the description
        const words = book.description.split(' ');
        book.description = words.slice(0, 50).join(' ');
        if (words.length > 50) {
            book.description += ' ...';
        }

        // Check the book object to ensure reviews have formattedDate
        console.log('Final reviews sent to template:', reviewsWithFormattedDate);

        // Calculate the total number of reviews
        const reviewCount = book.reviews.length;

        // Render the book details page
        res.render('book_details', { 
            title: book.title, 
            book: { ...book._doc, reviews: reviewsWithFormattedDate },  
            content: "", 
            loggedIn, 
            reviews: reviewsWithFormattedDate,
            userId: userIdStr,
            reviewCount // Pass the review count to the template
        });
    } catch (error) {
        console.error('Error fetching book details:', error);
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
        // Query the database for books belonging to the specified genre
        const books = await Book.find({ genre });

        // Query the database for the genre description
        const genreDescription = await Genre.findOne({ name: genre });

        // Query the database for all genres
        const allGenres = await Genre.find({});

        // Render the category page with the list of books and genre description
        res.render('category', { 
            title: genre.charAt(0).toUpperCase() + genre.slice(1), // Capitalize the first letter
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

app.use(attachCSRFToken);
app.get('/admin', async (req, res) => {
    const errors = req.query.errors ? JSON.parse(req.query.errors) : [];
    const csrfToken = req.csrfToken;
    res.render('admin', { title: 'admin', errors: errors, content: '', csrfToken: csrfToken });
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

// Route to display the delete book page
app.get('/admin/delete_book', isAdmin, async (req, res) => {
    try {
        const books = await Book.find({});
        const csrfToken = req.csrfToken;
        res.render('delete_book', { title: 'Delete Book', books, csrfToken, content:''});
    } catch (error) {
        console.error('Error fetching books:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Route to handle book deletion
app.post('/admin/delete_book/:id', verifyCSRFToken, async (req, res) => {
    try {
        const book = await Book.findByIdAndDelete(req.params.id);
        if (!book) {
            return res.status(404).send('Book not found');
        }
        console.log('Book deleted successfully:', book);
        res.redirect('/admin/delete_book');
    } catch (error) {
        console.error('Error deleting book:', error);
        res.status(500).send('Internal Server Error');
    }
});


app.get('/admin/edit_book', isAdmin, async (req, res) => {
    try {
        const books = await Book.find();
        const errors = req.query.errors ? JSON.parse(req.query.errors) : [];
        const csrfToken = req.csrfToken;
        res.render('edit_book', { title: 'admin', errors: errors, content: '', csrfToken: csrfToken, books });
    } catch (error) {
        console.error('Error fetching books:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/admin/edit_genre', isAdmin, async (req, res) => {
    try {
        const genres = await Book.distinct('genre');
        const errors = req.query.errors ? JSON.parse(req.query.errors) : [];
        const csrfToken = req.csrfToken;
        res.render('edit_genre', { title: 'admin', errors: errors, content: '', csrfToken: csrfToken, genres });
    } catch (error) {
        console.error('Error fetching genres:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/admin/edit_genre/:genre', isAdmin, async (req, res) => {
    const { genre } = req.params;
    try {
        const genreDescription = await Genre.findOne({ name: genre });
        const errors = req.query.errors ? JSON.parse(req.query.errors) : [];
        const csrfToken = req.csrfToken;
        res.render('edit_genre_form', { title: `Edit Genre: ${genre}`, errors: errors, csrfToken: csrfToken, genre, description: genreDescription ? genreDescription.description : '', content:'' });
    } catch (error) {
        console.error('Error fetching genre description:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/admin/update_genre', verifyCSRFToken, async (req, res) => {
    const { genre, description } = req.body;
    try {
        await Genre.findOneAndUpdate({ name: genre }, { description }, { upsert: true });
        console.log("update of genre successful and is " + description)
        res.redirect('/admin/edit_genre');
    } catch (error) {
        console.error('Error updating genre description:', error);
        const errors = JSON.stringify([{ msg: 'Error updating genre description.' }]);
        res.redirect(`/admin/edit_genre/${genre}?errors=${errors}`);
    }
});



// Route to display the edit form for a specific book
app.get('/admin/edit_book/:id', isAdmin, async (req, res) => {
    try {
        const book = await Book.findById(req.params.id);
        if (!book) {
            return res.status(404).send('Book not found');
        }
        const errors = req.query.errors ? JSON.parse(req.query.errors) : [];
        const csrfToken = req.csrfToken;
        res.render('edit_book_form', { title: 'Edit Book', book, errors, csrfToken, content: '', });
    } catch (error) {
        console.error('Error fetching book:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/admin/update_book/:id', upload.single('image'), verifyCSRFToken, async (req, res) => {
    try {
        const { title, author, description, genre, pages, mediaType, publishedDate } = req.body;
        const book = await Book.findById(req.params.id);

        if (!book) {
            return res.status(404).send('Book not found');
        }

        // Update book fields
        book.title = title;
        book.author = author;
        book.description = description;
        book.genre = Array.isArray(genre) ? genre : [genre];
        book.pages = parseInt(pages, 10);
        book.mediaType = mediaType;
        book.publishedDate = new Date(publishedDate);

        // If a new image is uploaded, update the image field
        if (req.file) {
            book.image = `/uploads/${req.file.filename}`;
        }

        await book.save();
        console.log('Book updated successfully:', book);
        res.redirect('/admin/edit_book');
    } catch (error) {
        console.error('Error updating book:', error);
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

// Define formatDate function to format the date
function formatDate(dateString) {
    // Ensure dateString is parsed into a Date object
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

app.get('/comments/list', async (req, res) => {
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

        // Fetch comments made by the current user
        const userComments = await Book.find({ 'reviews.comments.user': userId })
            .populate({
                path: 'reviews',
                populate: {
                    path: 'user',
                    select: 'fullName' // Select only the fullName field of the user who authored the review
                }
            })
            .populate({
                path: 'reviews.user', // Populate the user who authored the review
                select: 'fullName _id' // Select fullName and _id
            })
            .populate({
                path: 'reviews.comments.user',
                select: 'fullName' // Select only the fullName field of the user who made the comment
            });

        // Extract review details from userComments
        const reviewsWithUserComments = userComments.map(book => {
            return book.reviews.map(review => {
                const userComment = review.comments.find(comment => comment.user._id.equals(userId));
                if (userComment) {
                    return {
                        bookTitle: book.title,
                        reviewContent: review.content,
                        commenterName: userComment.user.fullName, // Access the commenter's fullName from the user object
                        commenterId: userComment.user._id, // Access the commenter's ID from the user object
                        commentCreatedAt: formatDate(userComment.createdAt), // Format the creation date of the comment
                        reviewAuthorName: review.user.fullName, // Access the fullName of the user who authored the review
                        reviewAuthorId: review.user._id, // Access the ID of the user who authored the review
                        bookId: book._id,
                        bookImage: book.image,
                        commentContent: userComment.content
                    };
                }
                // If userComment is undefined, return an empty object
                return {};
            });
        }).flat(); // Flatten the array of arrays

        // Remove empty objects from the array
        const filteredComments = reviewsWithUserComments.filter(comment => Object.keys(comment).length !== 0);

        // Render the comments list page with formatted dates
        res.render('comments', {
            title: 'Your Comments',
            comments: filteredComments,
            content: '',
            formatDate: formatDate, // Pass the formatDate function to the template
            firstName: firstName // Pass the first name to the template
        });
    } catch (error) {
        console.error('Error fetching user comments:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/comments/delete', async (req, res) => {
    const { commenterId, bookId } = req.body;

    try {
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

// app.get('/edit_favorite_genre' route handler
app.get('/edit_favorite_genre', async (req, res) => {
    try {
        // Fetch user details to get the selected genres
        const { loggedIn, userId } = determineLoggedInStatus(req);
        const csrfToken = req.csrfToken;

        if (!loggedIn) {
            return res.redirect('/login'); // Redirect to login if user not logged in
        }

        const user = await User.findById(userId).select('selectedGenres');

        if (!user) {
            return res.status(404).send('User not found');
        }

        const selectedGenres = user.selectedGenres;

        // Render the edit favorite genres page with selected genres
        res.render('edit_favorite_genres', {
            title: 'Edit Favorite Genres',
            selectedGenres: selectedGenres,
            content: '',
            csrfToken: csrfToken
        });
    } catch (error) {
        console.error('Error fetching user details:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Add this POST route to handle the favorite genres form submission
app.post('/edit_favorite_genre', async (req, res) => {
    try {
        const { loggedIn, userId } = determineLoggedInStatus(req);

        if (!loggedIn) {
            return res.redirect('/login'); // Redirect to login if user not logged in
        }

        const { genre } = req.body;

        // Ensure genre is an array, even if only one genre is selected
        const selectedGenres = Array.isArray(genre) ? genre : [genre];

        // Update the user's selected genres
        await User.findByIdAndUpdate(userId, { selectedGenres: selectedGenres });

        res.redirect('/'); // Redirect to a relevant page after updating
    } catch (error) {
        console.error('Error updating favorite genres:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/account_settings', (req, res) => {
    res.redirect('/account_settings/profile');
});

app.use('/account_settings', accountSettingsRouter);
app.get('/delete_account', async (req, res) => {
    try {
        // Determine user logged in status and get the user ID
        const { loggedIn, userId } = determineLoggedInStatus(req);
        const csrfToken = req.csrfToken;

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

        // Fetch comments made by the current user
        const userComments = await Book.find({ 'reviews.comments.user': userId })
            .populate({
                path: 'reviews',
                populate: {
                    path: 'user',
                    select: 'fullName' // Select only the fullName field of the user who authored the review
                }
            })
            .populate({
                path: 'reviews.user', // Populate the user who authored the review
                select: 'fullName _id' // Select fullName and _id
            })
            .populate({
                path: 'reviews.comments.user',
                select: 'fullName' // Select only the fullName field of the user who made the comment
            });

        // Extract review details from userComments
        const reviewsWithUserComments = userComments.map(book => {
            return book.reviews.map(review => {
                const userComment = review.comments.find(comment => comment.user._id.equals(userId));
                if (userComment) {
                    return {
                        bookTitle: book.title,
                        reviewContent: review.content,
                        commenterName: userComment.user.fullName, // Access the commenter's fullName from the user object
                        commenterId: userComment.user._id, // Access the commenter's ID from the user object
                        commentCreatedAt: formatDate(userComment.createdAt), // Format the creation date of the comment
                        reviewAuthorName: review.user.fullName, // Access the fullName of the user who authored the review
                        reviewAuthorId: review.user._id, // Access the ID of the user who authored the review
                        bookId: book._id,
                        bookImage: book.image,
                        commentContent: userComment.content
                    };
                }
                // If userComment is undefined, return an empty object
                return {};
            });
        }).flat(); // Flatten the array of arrays

        // Remove empty objects from the array
        const filteredComments = reviewsWithUserComments.filter(comment => Object.keys(comment).length !== 0);

        // Render the comments list page with formatted dates
        res.render('delete_account', {
            title: 'Your Comments',
            comments: filteredComments,
            content: '',
            formatDate: formatDate, // Pass the formatDate function to the template
            firstName: firstName, // Pass the first name to the template
            csrfToken:csrfToken
        });
    } catch (error) {
        console.error('Error fetching user comments:', error);
        res.status(500).send('Internal Server Error');
    }
});




app.get('/change_password', async (req, res) => {
    try {
        const { loggedIn, userId } = determineLoggedInStatus(req);
        const csrfToken = req.csrfToken;
        const errors = req.query.errors ? JSON.parse(req.query.errors) : [];
        const token = req.query.token;

        if (!loggedIn) {
            return res.redirect('/login'); // Redirect to login if user not logged in
        }

        const user = await User.findById(userId).select('email');

        if (!user) {
            return res.status(404).send('User not found');
        }

        res.render('change_password', {
            title: 'Change Password',
            user: user,
            csrfToken: csrfToken,
            loggedIn: loggedIn,
            content: '',
            errors:errors,
            token:token
        });
    } catch (error) {
        console.error('Error fetching user details:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/change_password', async (req, res) => {
    const { password: currentPassword, 'new-password': newPassword, 're-enter-password': confirmPassword } = req.body;
    const errors = [];
    const { loggedIn, userId } = determineLoggedInStatus(req);
    const csrfToken = req.csrfToken;

    if (!loggedIn) {
        errors.push('You must be logged in to change your password.');
        return res.render('change_password', { title: 'Change Password', errors, csrfToken });
    }

    if (newPassword !== confirmPassword) {
        errors.push('New password and confirmation password do not match.');
        return res.render('change_password', { title: 'Change Password', errors, csrfToken });
    }

    if (newPassword.length < 6) {
        errors.push('New password must be at least 6 characters long.');
        return res.render('change_password', { title: 'Change Password', errors, csrfToken });
    }

    try {
        const user = await User.findById(userId);

        if (!user) {
            errors.push('User not found.');
            return res.render('change_password', { title: 'Change Password', errors, csrfToken });
        }

        const isMatch = await bcrypt.compare(currentPassword, user.password);

        if (!isMatch) {
            errors.push('Current password is incorrect.');
            return res.render('change_password', { title: 'Change Password', errors, csrfToken });
        }

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);

        await user.save();

        res.redirect('/account_settings');
    } catch (error) {
        console.error('Error changing password:', error);
        errors.push('An unexpected error occurred. Please try again later.');
        res.status(500).render('change_password', { title: 'Change Password', errors, csrfToken });
    }
});

app.post('/delete_account', async (req, res) => {
    try {
        const { loggedIn, userId } = determineLoggedInStatus(req);
        if (!loggedIn) {
            return res.redirect('/login'); // Redirect to login if user not logged in
        }

        const { keepPostsAnonymously } = req.body;

        if (keepPostsAnonymously) {
            // Anonymize the user's reviews and comments
            await Book.updateMany(
                { 'reviews.user': userId },
                { '$set': { 'reviews.$[elem].user': null } }, // Set user to null
                { arrayFilters: [{ 'elem.user': userId }] }
            );
            await Book.updateMany(
                { 'reviews.comments.user': userId },
                { '$set': { 'reviews.$[review].comments.$[comment].user': null } }, // Set user to null
                { arrayFilters: [{ 'review.comments.user': userId }, { 'comment.user': userId }] }
            );
        }

        // Delete the user account
        await User.findByIdAndDelete(userId);

        res.redirect('/'); // Redirect to the homepage after account deletion
    } catch (error) {
        console.error('Error deleting account:', error);
        res.status(500).send('Internal Server Error');
    }
});


// Start the server
app.listen(port, () => {
    console.log(`MyReads app listening at http://localhost:${port}`);
});

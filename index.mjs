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

// Middleware to parse JSON bodies
app.use(bodyParser.json());

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
    const loggedIn = determineLoggedInStatus(req);
    try {
        // Fetch books from the database
        const books = await Book.find().sort({ createdAt: -1 })

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
        res.render('new_releases', { title: 'New Releases', loggedIn, content: '', books });
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
        const userIds = book.reviews.map(review => review.user._id);
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
            const likedByUser = userIdStr ? filteredLikes.map(like => like.toString()).includes(userIdStr) : false;

            // Format comment dates
            const commentsWithFormattedDate = review.comments
            .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))
                .map(comment => ({
                    ...comment._doc,
                    formattedDate: moment(comment.createdAt).format('MMMM D, YYYY')
                }));

            return {
                ...review._doc,
                formattedDate: formattedDate,
                truncatedContent: review.content.length > 200 ? review.content.slice(0, 200) + '...' : review.content,
                likedByUser: likedByUser,
                comments: commentsWithFormattedDate,
                commentCount: review.comments.length, // Include the total number of comments
                userReviewCount: reviewCountsMap[review.user._id.toString()] || 0 // Add total number of reviews for the user
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
            content:"", 
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
        const  { content }  = req.body;
        const { loggedIn, userId } = determineLoggedInStatus(req);

        console.log('Received comment content:', content);
        console.log('User logged in:', loggedIn);
        console.log('User ID:', userId);

        if (!loggedIn || !userId) {
            console.log('User not logged in or userId not found.');
            return res.status(401).json({ success: false, error: 'User not logged in' });
        }

        const user = await User.findById(userId);
        console.log('User found:', user);

        const book = await Book.findOne({ 'reviews._id': req.params.reviewId });
        console.log('Book found:', book);

        if (!user || !book) {
            console.log('User or book not found.');
            return res.status(404).json({ success: false, error: 'User or book not found' });
        }

        const review = book.reviews.id(req.params.reviewId);
        console.log('Review found:', review);

        if (typeof content !== 'string') {
            console.log('Invalid content type:', typeof content);
            return res.status(400).json({ success: false, error: 'Invalid content type' });
        }

        const trimmedContent = content.trim();
        console.log('Trimmed comment content:', trimmedContent);

        if (!trimmedContent) {
            console.log('Comment content is empty.');
            return res.status(400).json({ success: false, error: 'Comment content cannot be empty' });
        }

        // Sanitize content to prevent XSS
        const sanitizedContent = sanitizeHtml(trimmedContent, {
            allowedTags: [ 'p', 'br', 'i', 'b', 'u' ], // Allow only paragraph and line break tags
            allowedAttributes: {}
        });

        // Replace newlines with paragraph tags
        const formattedContent = sanitizedContent.split('\n').map(line => `<p>${line}</p>`).join('');
        console.log('Formatted comment content:', formattedContent);

        review.comments.push({ content: formattedContent, user: userId });
        console.log('Comment added to review:', review.comments);

        await book.save();
        console.log('Book saved after adding comment.');

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
        // Determine user logged in status and get the user ID
        const { loggedIn, userId } = determineLoggedInStatus(req);
        const userIdStr = userId ? userId.toString() : null;

        if (!userIdStr) {
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

        // Filter out null values from the likes array
        review.likes = review.likes.filter(like => like !== null);

        const isLiked = review.likes.map(like => like.toString()).includes(userIdStr);
        if (isLiked) {
            review.likes.pull(userIdStr); // Unlike
        } else {
            review.likes.push(userIdStr); // Like
        }

        await book.save();
        res.json({ likes: review.likes.length, liked: !isLiked });
    } catch (error) {
        console.error('Error liking review:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


app.get('/genre/:genre', async (req, res) => {
    const { genre } = req.params;

    try {
        const loggedIn = determineLoggedInStatus(req);
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

// Middleware to check if the user is an admin
const isAdmin = (req, res, next) => {
    // Extract the JWT token from the request cookies
    const token = req.cookies.token;

    // Check if the token exists
    if (!token) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    try {
        // Verify the token
        const decoded = jwt.verify(token, process.env.SECRET);

        // Check if the decoded token contains the user's role (isAdmin)
        if (decoded && decoded.isAdmin) {
            // User is an admin, proceed to the next middleware
            next();
        } else {
            // User is not an admin, return unauthorized
            return res.status(403).json({ message: 'Forbidden' });
        }
    } catch (error) {
        console.error('Error verifying JWT token:', error);
        return res.status(500).json({ message: 'Internal Server Error' });
    }
};

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

app.get('/admin/add_book', isAdmin, async (req, res) => {
    const errors = req.query.errors ? JSON.parse(req.query.errors) : [];
    const csrfToken = req.csrfToken;
    res.render('add_book', { title: 'admin', errors: errors, content: '', csrfToken: csrfToken });
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



app.post('/admin/add_book', upload.single('image'), verifyCSRFToken, async (req, res) => {
    const errors = [];
    const { title, author, description, genre, pages, mediaType, publishedDate } = req.body;
    const imagePath = `/uploads/${req.file.filename}`;

     // Sanitize the description
     const sanitizedDescription = sanitizeHtml(description, {
        allowedTags: sanitizeHtml.defaults.allowedTags.concat(['h1', 'h2', 'img']),
        allowedAttributes: {
            a: ['href', 'name', 'target'],
            img: ['src', 'alt'],
            '*': ['style', 'class']
        }
    });

    const newBook = new Book({
        image: imagePath,
        title,
        author,
        description: sanitizedDescription,
        genre: Array.isArray(genre) ? genre : [genre],
        pages: parseInt(pages, 10),
        mediaType,
        publishedDate: new Date(publishedDate)
    });
    await newBook.save();
    console.log('Book created successfully:', newBook);
    res.redirect('/');
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

    res.render('mybooks', { title: "Stephen Owabie's books on Myreads", errors: errors, content: '', 
    csrfToken: csrfToken, loggedIn, books: booksWithUserReviews, searchQuery: searchQuery});
});

app.get('/user/:userId/mybooks', async (req, res) => {
    const { loggedIn, userId } = determineLoggedInStatus(req);
    const targetUserId = req.params.userId;
    
    if (userId === targetUserId) {
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



// Start the server
app.listen(port, () => {
    console.log(`MyReads app listening at http://localhost:${port}`);
});

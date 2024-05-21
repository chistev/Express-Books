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
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import _ from 'lodash';
import sanitizeHtml from 'sanitize-html';
import { JSDOM } from 'jsdom';
import createDOMPurify from 'dompurify';



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

// Route for the home page
app.get('/', async (req, res) => {
    // Determine the loggedIn status
    const loggedIn = determineLoggedInStatus(req);

    res.render('index', { title: 'Free Online Books', loggedIn, content: '' });
});

// Add a route to handle logout
app.post('/logout', (req, res) => {
    // Clear the token cookie
    res.clearCookie('token');
    // Redirect the user to the sign-in page
    res.redirect('/');
});

// Redirect users to the index page when they visit /myreads
app.get('/myreads', (req, res) => {
    res.redirect('/');
});

// Redirect users to the sign-up page when they visit /signup
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
        const loggedIn = determineLoggedInStatus(req);
        // Fetch the book from the database by ID
        const book = await Book.findById(req.params.id);
        if (!book) {
            return res.status(404).send('Book not found');
        }

         // Create a truncated version of the description
         const words = book.description.split(' ');
         book.description = words.slice(0, 20).join(' ');
         if (words.length > 20) {
            book.description += ' ...';
         }

        // Render the book details page
        res.render('book_details', { title: book.title, book, content:"", loggedIn });
    } catch (error) {
        console.error('Error fetching book details:', error);
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

app.get('/admin/add_book', isAdmin, async (req, res) => {
    const errors = req.query.errors ? JSON.parse(req.query.errors) : [];
    const csrfToken = req.csrfToken;
    res.render('add_book', { title: 'admin', errors: errors, content: '', csrfToken: csrfToken });
});

app.post('/admin/add_book', upload.single('image'), verifyCSRFToken, async (req, res) => {
    const errors = [];
    const { title, author, rating, description } = req.body;
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
        rating,
        description: sanitizedDescription
    });
    await newBook.save();
    console.log('Book created successfully:', newBook);
    res.redirect('/');
}); 




// Start the server
app.listen(port, () => {
    console.log(`MyReads app listening at http://localhost:${port}`);
});

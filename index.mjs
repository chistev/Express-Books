import express from 'express';
import session from 'express-session';
import dotenv from 'dotenv';
import registerController from './controllers/registerController.mjs';
import otpRequestController from './controllers/otpRequestController.mjs';
import otpResendController from './controllers/otpResendController.mjs';
import favoriteGenreController from './controllers/favoriteGenreController.mjs'

dotenv.config();
const app = express();
const port = 3000;

// Configure express-session middleware
app.use(session({
    secret: process.env.SECRET, // Use the SECRET environment variable
    resave: false,
    saveUninitialized: true
}));

// Use express.static middleware to serve static files
app.use(express.static('public'));

// Set EJS as the view engine
app.set('view engine', 'ejs');

// Middleware to parse URL-encoded form data
app.use(express.urlencoded({ extended: true }));

app.use('/register', registerController);
app.use('/otp-request', otpRequestController);
app.use('/resend-otp', otpResendController);
app.use('/favorite-genre', favoriteGenreController);

// Define routes
app.get('/', (req, res) => {
    res.render('index', { title: 'MyReads', message: 'Welcome to MyReads!' });
});

// Redirect users to the index page when they visit /myreads
app.get('/myreads', (req, res) => {
    res.redirect('/');
});

// Redirect users to the sign-up page when they visit /signup
app.get('/signup', (req, res) => {
    res.render('signup', { title: 'Sign Up', message: 'Sign up for MyReads!' });
});

// Start the server
app.listen(port, () => {
    console.log(`MyReads app listening at http://localhost:${port}`);
});

import express from 'express';
import session from 'express-session';
import dotenv from 'dotenv';
import registerController from './controllers/registerController.mjs'; // Importing the router
import otpRequestController from './controllers/otpRequestController.mjs';
import otpResendController from './controllers/otpResendController.mjs'

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

// Attach the registerController router
app.use('/register', registerController);

app.use('/otp-request', otpRequestController);
app.use('/resend-otp', otpResendController);

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

// Define route for /favorite-genre
app.get('/favorite-genre', (req, res) => {
    // Render the favorite-genre view
    res.render('favorite-genre', { title: 'Favorite Genre' });
});

// Define route for /favorite-genre POST request
app.post('/favorite-genre', (req, res) => {
    // Extract selected genres from the form submission
    const selectedGenres = req.body.genre;
    console.log(selectedGenres)

    // Save selected genres to the session
    req.session.selectedGenres = selectedGenres;

    // Redirect to the next step or page
    res.redirect('/'); // Change '/next-page' to the actual URL of the next step
});


// Start the server
app.listen(port, () => {
    console.log(`MyReads app listening at http://localhost:${port}`);
});

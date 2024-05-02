import express from 'express';
import session from 'express-session';
import dotenv from 'dotenv';
import registerController from './controllers/registerController.mjs'; // Importing the router
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

// Set the maximum number of OTP attempts allowed
const MAX_OTP_ATTEMPTS = 3;

app.get('/otp-request', (req, res) => {
    const email = req.session.email; // Retrieve email from query parameters
    const errors = req.query.errors ? JSON.parse(req.query.errors) : []; // Parse errors from query parameters if they exist
    const otpAttempts = req.session.otpAttempts || 0; // Get the number of OTP attempts from the session or initialize to 0
    const newOTPRequest = req.session.newOTPRequest; // Check if a new OTP request has been made

    // Clear the newOTPRequest flag from the session
    req.session.newOTPRequest = false;

    res.render('otp-request', { title: 'OTP Request', email: email,  errors: errors, otpAttempts: otpAttempts, newOTPRequest: newOTPRequest});
});

app.post('/otp-request', async (req, res) => {
    const enteredOTP = req.body.otp; // Retrieve OTP entered by the user
    const generatedOTP = req.session.otp;
    const fullName = req.session.fullName; // Retrieve fullName from session
    const email = req.session.email; // Retrieve email from session
    const otpAttempts = req.session.otpAttempts || 0; // Get the number of OTP attempts from the session or initialize to 0
    
    
    console.log('Entered OTP:', enteredOTP);
    console.log('Generated OTP:', generatedOTP);
    console.log('Full Name:', fullName);
    console.log('Email:', email);
    console.log('OTP Attempts:', otpAttempts);

    // Array to store validation errors
    const errors = [];
    
    if (enteredOTP === generatedOTP) {
        console.log('OTP validation successful.'); // Console success message
        // Redirect the user to the favorite-genre page if OTP verification passes
        return res.redirect('/favorite-genre');
    } else {
        console.error('Invalid OTP.'); // Console error message
        errors.push('Invalid OTP');

        // Increment the OTP attempts counter in the session
        req.session.otpAttempts = otpAttempts + 1;

        // If maximum attempts reached, generate a new OTP and reset the attempts counter
        if (otpAttempts >= MAX_OTP_ATTEMPTS) {
            console.log('Maximum OTP attempts reached. Sending new OTP...');
            req.session.otp = generateOTP();
            req.session.otpAttempts = 0;

            // Set flag to indicate a new OTP request has been made
            req.session.newOTPRequest = true;

            // Send the new OTP to the provided email
            try {
                console.log('Sending new OTP to email:', email);
                await sendEmail(email, fullName, req.session.otp);
                console.log('New OTP sent successfully.');
            } catch (error) {
                console.error('Error sending email:', error);
                res.status(500).send('Error sending email');
                return; // Return to prevent further execution
            }
        }
    }

    if (errors.length > 0 || otpAttempts >= MAX_OTP_ATTEMPTS) {
        console.log('Redirecting to otp-request page with errors:', errors);
        return res.redirect('/otp-request?errors=' + encodeURIComponent(JSON.stringify(errors)));
    }
});

// Add a new route to handle the request for resending OTP
app.get('/resend-otp', async (req, res) => {
    const email = req.session.email; // Retrieve email from session
    const fullName = req.session.fullName; // Retrieve fullName from session

    // Generate a new OTP
    const newOTP = generateOTP();

    // Update session with the new OTP
    req.session.otp = newOTP;
    req.session.otpAttempts = 0; // Reset OTP attempts counter

    // Send the new OTP to the provided email
    try {
        await sendEmail(email, fullName, newOTP);
        console.log('New OTP sent successfully.');
        // Set flag to indicate a new OTP request has been made
        req.session.newOTPRequest = true;
    } catch (error) {
        console.error('Error sending email:', error);
        res.status(500).send('Error sending email');
        return; // Return to prevent further execution
    }

    // Redirect back to the OTP validation logic
    res.redirect('/otp-request');
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

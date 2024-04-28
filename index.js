const express = require('express');
const app = express();
const port = 3000; // Choose a port for your server

// Use express.static middleware to serve static files
app.use(express.static('public'));

// Set EJS as the view engine
app.set('view engine', 'ejs');

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

const express = require('express');
const app = express();
const port = 3000; // Choose a port for your server

// Define routes
app.get('/', (req, res) => {
    res.send('Welcome to MyReads!');
});

// Start the server
app.listen(port, () => {
    console.log(`MyReads app listening at http://localhost:${port}`);
});

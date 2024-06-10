import csrf from 'csrf';

const tokens = new csrf();
const secret = tokens.secretSync();

// function to generate and attach CSRF token to the request object
export const attachCSRFToken = (req, res, next) => {
    const token = tokens.create(secret);
    res.cookie('_csrf', token); // Set CSRF token in a cookie
    req.csrfToken = token; // Optionally attach token to request object (for rendering views)
    next();
};

export const verifyCSRFToken = (req, res, next) => {
    const csrfToken = req.body._csrf || req.cookies._csrf; // Check both body and cookies
    if (!tokens.verify(secret, csrfToken)) {
        // Invalid CSRF token
        const errors = ['CSRF token verification failed'];
        return res.redirect('/register?errors=' + encodeURIComponent(JSON.stringify(errors)));
    }
    next();
};

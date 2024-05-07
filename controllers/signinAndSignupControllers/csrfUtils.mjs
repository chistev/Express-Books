import csrf from 'csrf';

const tokens = new csrf();
const secret = tokens.secretSync();

// function to generate and attach CSRF token to the request object
export const attachCSRFToken = (req, res, next) => {
    const token = tokens.create(secret);
    req.csrfToken = token;
    next();
};

export const verifyCSRFToken = (req, res, next) => {
    const csrfToken = req.body._csrf;
    if (!tokens.verify(secret, csrfToken)) {
        // Invalid CSRF token
        const errors = ['CSRF token verification failed'];
        return res.redirect('/register?errors=' + encodeURIComponent(JSON.stringify(errors)));
    }
    next();
};
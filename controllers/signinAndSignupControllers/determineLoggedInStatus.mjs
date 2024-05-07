import jwt from 'jsonwebtoken';
import crypto from 'crypto';

export function determineLoggedInStatus(req) {
    let loggedIn = false;

    const token = req.cookies.token;

    if (token) {
        try {
            jwt.verify(token, process.env.SECRET);
            loggedIn = true;
        } catch (error) {
            console.error('Error verifying token:', error.message);
        }
    } else if (req.session.signInToken) {
        loggedIn = true;
    }
    return loggedIn;
}

export function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

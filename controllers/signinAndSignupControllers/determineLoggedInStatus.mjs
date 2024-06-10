import jwt from 'jsonwebtoken';
import crypto from 'crypto';

export function determineLoggedInStatus(req) {
    let loggedIn = false;
    let userId = null; 

    const token = req.cookies.token;
    console.log("Token from cookies:", token);

    if (token) {
        try {
            const decodedToken = jwt.verify(token, process.env.SECRET); 
            console.log("Decoded token:", decodedToken);
            loggedIn = true;
            userId = decodedToken.userId;
        } catch (error) {
            console.error('Error verifying token:', error.message);
        }
    } else if (req.session.signInToken) {
        loggedIn = true;
        userId = req.session.userId;
        console.log("User ID from session:", userId);
    }
    console.log("logged in " + loggedIn + "UserId " + userId)
    return { loggedIn, userId };
}

export function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

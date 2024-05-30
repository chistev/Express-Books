import jwt from 'jsonwebtoken';
import crypto from 'crypto';

export function determineLoggedInStatus(req) {
    let loggedIn = false;
    let userId = null; // Define userId variable

    const token = req.cookies.token;
    console.log("Token from cookies:", token);

    if (token) {
        try {
            const decodedToken = jwt.verify(token, process.env.SECRET); // Verify and decode token
            console.log("Decoded token:", decodedToken);
            loggedIn = true;
            userId = decodedToken.userId; // Assuming user ID is stored in the JWT payload as 'userId'
        } catch (error) {
            console.error('Error verifying token:', error.message);
        }
    } else if (req.session.signInToken) {
        loggedIn = true;
        // Set userId if available in the session
        userId = req.session.userId;
        console.log("User ID from session:", userId);
    }
    console.log("logged in " + loggedIn + "UserId " + userId)
    return { loggedIn, userId }; // Return loggedIn status and userId
}

export function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

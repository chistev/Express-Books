import User from '../models/User.mjs';
import { determineLoggedInStatus } from '../controllers/signinAndSignupControllers/determineLoggedInStatus.mjs';

// Middleware function to fetch user information for notifications
const fetchUserForNotifications = async (req, res, next) => {
    try {
        // Fetch user information based on the logged-in user's ID
        const { loggedIn, userId } = determineLoggedInStatus(req);
        if (loggedIn) {
            const user = await User.findById(userId);
            if (user) {
                req.user = user; // Attach user object to the request
            }
        }
        next(); // Move to the next middleware or route handler
    } catch (error) {
        console.error('Error fetching user information for notifications:', error);
        next(error); // Pass error to the error handling middleware
    }
};

export default fetchUserForNotifications;

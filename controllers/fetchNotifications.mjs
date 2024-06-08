import User from '../models/User.mjs';
import { determineLoggedInStatus } from '../controllers/signinAndSignupControllers/determineLoggedInStatus.mjs';

const fetchNotifications = async (req, res, next) => {
    const { loggedIn, userId } = determineLoggedInStatus(req);
    console.log(`LoggedIn: ${loggedIn}, UserId: ${userId}`);
    if (loggedIn && userId) {
        try {
            const user = await User.findById(userId).select('notifications');
            console.log(`Notifications for user ${userId}:`, user.notifications);
            res.locals.notifications = user.notifications;
        } catch (error) {
            console.error('Error fetching notifications:', error);
            res.locals.notifications = [];
        }
    } else {
        res.locals.notifications = [];
    }
    next();
};

export default fetchNotifications;

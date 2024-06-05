import User from '../models/User.mjs';
import { determineLoggedInStatus } from '../controllers/signinAndSignupControllers/determineLoggedInStatus.mjs';

async function addUserToLocals(req, res, next) {
    const { loggedIn, userId } = determineLoggedInStatus(req);

    if (loggedIn && userId) {
        try {
            const user = await User.findById(userId);
            if (user) {
                res.locals.loggedIn = true;
                res.locals.user = user;
            } else {
                res.locals.loggedIn = false;
                res.locals.user = null;
            }
        } catch (error) {
            console.error('Error fetching user data:', error);
            res.locals.loggedIn = false;
            res.locals.user = null;
        }
    } else {
        res.locals.loggedIn = false;
        res.locals.user = null;
    }

    next();
}

export default addUserToLocals;

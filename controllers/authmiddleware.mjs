import User from '../models/User.mjs';
import { determineLoggedInStatus } from '../controllers/signinAndSignupControllers/determineLoggedInStatus.mjs';

async function addUserToLocals(req, res, next) {
    const { loggedIn, userId } = determineLoggedInStatus(req);

    if (loggedIn && userId) {
        try {
            const user = await User.findById(userId);
            if (user) {
                const [firstName, lastName] = user.fullName.split(' ');
                res.locals.loggedIn = true;
                res.locals.user = user;
                res.locals.firstName = firstName;
                res.locals.lastName = lastName;
            } else {
                res.locals.loggedIn = false;
                res.locals.user = null;
                res.locals.firstName = '';
                res.locals.lastName = '';
            }
        } catch (error) {
            console.error('Error fetching user data:', error);
            res.locals.loggedIn = false;
            res.locals.user = null;
            res.locals.firstName = '';
            res.locals.lastName = '';
        }
    } else {
        res.locals.loggedIn = false;
        res.locals.user = null;
        res.locals.firstName = '';
        res.locals.lastName = '';
    }

    next();
}

export default addUserToLocals;

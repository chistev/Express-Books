import express from 'express';
import User from '../../models/User.mjs';
import { attachCSRFToken, verifyCSRFToken } from '../signinAndSignupControllers/csrfUtils.mjs';
import addUserToLocals from '../../controllers/authmiddleware.mjs'
import bcrypt from 'bcryptjs'; 

const router = express.Router();
router.use(attachCSRFToken);
router.use(addUserToLocals);

router.get('/change_password', async (req, res) => {
    try {
        const csrfToken = req.csrfToken;
        const errors = req.query.errors ? JSON.parse(req.query.errors) : [];

        if (!res.locals.loggedIn) {
            return res.redirect('/signin');
        }

        if (!res.locals.user) {
            return res.status(404).send('User not found');
        }

        res.render('account_settings/change_password', {
            title: 'Change Password',
            csrfToken: csrfToken,
            loggedIn: res.locals.loggedIn,
            user: res.locals.user,
            content: '',
            errors: errors,
        });
    } catch (error) {
        console.error('Error fetching user details:', error);
        res.status(500).send('Internal Server Error');
    }
});

router.post('/change_password', verifyCSRFToken, async (req, res) => {
    const { password: currentPassword, 'new-password': newPassword, 're-enter-password': confirmPassword } = req.body;
    const errors = [];
    const csrfToken = req.csrfToken;

    if (!res.locals.loggedIn) {
        errors.push('You must be logged in to change your password.');
        return res.render('change_password', {
            title: 'Change Password',
            csrfToken: csrfToken,
            loggedIn: res.locals.loggedIn,
            user: res.locals.user,
            content: '',
            errors: errors,
        });
    }

    if (newPassword !== confirmPassword) {
        errors.push('New password and confirmation password do not match.');
        return res.render('change_password', {
            title: 'Change Password',
            csrfToken: csrfToken,
            loggedIn: res.locals.loggedIn,
            user: res.locals.user,
            content: '',
            errors: errors,
        });
    }

    if (newPassword.length < 6) {
        errors.push('New password must be at least 6 characters long.');
        return res.render('change_password', {
            title: 'Change Password',
            csrfToken: csrfToken,
            loggedIn: res.locals.loggedIn,
            user: res.locals.user,
            content: '',
            errors: errors,
        });
    }

    try {
        const user = await User.findById(res.locals.user._id);

        if (!user) {
            errors.push('User not found.');
            return res.render('change_password', {
                title: 'Change Password',
                csrfToken: csrfToken,
                loggedIn: res.locals.loggedIn,
                user: res.locals.user,
                content: '',
                errors: errors,
            });
        }

        const isMatch = await bcrypt.compare(currentPassword, user.password);

        if (!isMatch) {
            errors.push('Current password is incorrect.');
            return res.render('change_password', {
                title: 'Change Password',
                csrfToken: csrfToken,
                loggedIn: res.locals.loggedIn,
                user: res.locals.user,
                content: '',
                errors: errors,
            });
        }

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);

        await user.save();

        res.redirect('/account_settings');
    } catch (error) {
        console.error('Error changing password:', error);
        errors.push('An unexpected error occurred. Please try again later.');
        res.status(500).render('change_password', {
            title: 'Change Password',
            csrfToken: csrfToken,
            loggedIn: res.locals.loggedIn,
            user: res.locals.user,
            content: '',
            errors: errors,
        });
    }
});

export default router;
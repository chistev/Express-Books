import express from 'express';
import User from '../../models/User.mjs';
import { attachCSRFToken, verifyCSRFToken } from '../signinAndSignupControllers/csrfUtils.mjs';
import { determineLoggedInStatus } from '../signinAndSignupControllers/determineLoggedInStatus.mjs';

const router = express.Router();
router.use(attachCSRFToken);

router.get('/', async (req, res) => {
    try {
        const { loggedIn } = determineLoggedInStatus(req);
        const csrfToken = req.csrfToken;

        if (!loggedIn) {
            return res.redirect('/signin');
        }

        res.render('account_settings/delete_account', {
            title: 'Delete Your Account',
            content: '',
            csrfToken:csrfToken
        });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).send('Internal Server Error');
    }
});

router.post('/', verifyCSRFToken, async (req, res) => {
    try {
        const { loggedIn, userId } = determineLoggedInStatus(req);
        if (!loggedIn) {
            return res.redirect('/signin');
        }

        const { keepPostsAnonymously } = req.body;

        if (keepPostsAnonymously) {
            await Book.updateMany(
                { 'reviews.user': userId },
                { '$set': { 'reviews.$[elem].user': null } },
                { arrayFilters: [{ 'elem.user': userId }] }
            );
            await Book.updateMany(
                { 'reviews.comments.user': userId },
                { '$set': { 'reviews.$[review].comments.$[comment].user': null } },
                { arrayFilters: [{ 'review.comments.user': userId }, { 'comment.user': userId }] }
            );
        }

        await User.findByIdAndDelete(userId);

        res.redirect('/logout');
    } catch (error) {
        console.error('Error deleting account:', error);
        res.status(500).send('Internal Server Error');
    }
});

export default router;
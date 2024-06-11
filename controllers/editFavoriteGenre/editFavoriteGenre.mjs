import express from 'express';
import User from '../../models/User.mjs';
import { attachCSRFToken, verifyCSRFToken } from '../signinAndSignupControllers/csrfUtils.mjs';
import { determineLoggedInStatus } from '../signinAndSignupControllers/determineLoggedInStatus.mjs';

const router = express.Router();
router.use(attachCSRFToken);


router.get('/', async (req, res) => {
    try {
        const { loggedIn, userId } = determineLoggedInStatus(req);
        const csrfToken = req.csrfToken;

        if (!loggedIn) {
            return res.redirect('/signin'); 
        }

        const user = await User.findById(userId).select('selectedGenres');

        if (!user) {
            return res.status(404).send('User not found');
        }

        const selectedGenres = user.selectedGenres;

        res.render('edit_favorite_genres', {
            title: 'Edit Favorite Genres',
            selectedGenres: selectedGenres,
            content: '',
            csrfToken: csrfToken
        });
    } catch (error) {
        console.error('Error fetching user details:', error);
        res.status(500).send('Internal Server Error');
    }
});


router.post('/', verifyCSRFToken, async (req, res) => {
    try {
        const { loggedIn, userId } = determineLoggedInStatus(req);

        if (!loggedIn) {
            return res.redirect('/signin');
        }

        const { genre } = req.body;

        // Ensure genre is an array, even if only one genre is selected
        const selectedGenres = Array.isArray(genre) ? genre : [genre];

        await User.findByIdAndUpdate(userId, { selectedGenres: selectedGenres });

        res.redirect('/');
    } catch (error) {
        console.error('Error updating favorite genres:', error);
        res.status(500).send('Internal Server Error');
    }
});

export default router;
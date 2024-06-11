import express from 'express';
import { isAdmin } from './isAdmin.mjs';
import { attachCSRFToken, verifyCSRFToken } from '../signinAndSignupControllers/csrfUtils.mjs';
import Genre from '../../models/Genre.mjs';

const router = express.Router();

router.use(attachCSRFToken);

router.get('/admin/edit_genre', isAdmin, async (req, res) => {
    try {
        const genres = await Book.distinct('genre');
        const errors = req.query.errors ? JSON.parse(req.query.errors) : [];
        const csrfToken = req.csrfToken;
        res.render('admin/edit_genre', { title: 'admin', errors: errors, content: '', csrfToken: csrfToken, genres });
    } catch (error) {
        console.error('Error fetching genres:', error);
        res.status(500).send('Internal Server Error');
    }
});

router.get('/admin/edit_genre/:genre', isAdmin, async (req, res) => {
    const { genre } = req.params;
    try {
        const genreDescription = await Genre.findOne({ name: genre });
        const errors = req.query.errors ? JSON.parse(req.query.errors) : [];
        const csrfToken = req.csrfToken;
        res.render('admin/edit_genre_form', { title: `Edit Genre: ${genre}`, errors: errors, csrfToken: csrfToken, genre, description: genreDescription ? genreDescription.description : '', content:'' });
    } catch (error) {
        console.error('Error fetching genre description:', error);
        res.status(500).send('Internal Server Error');
    }
});


router.post('/admin/update_genre', verifyCSRFToken, async (req, res) => {
    const { genre, description } = req.body;
    try {
        await Genre.findOneAndUpdate({ name: genre }, { description }, { upsert: true });
        console.log("update of genre successful and is " + description)
        res.redirect('/admin/edit_genre');
    } catch (error) {
        console.error('Error updating genre description:', error);
        const errors = JSON.stringify([{ msg: 'Error updating genre description.' }]);
        res.redirect(`/admin/edit_genre/${genre}?errors=${errors}`);
    }
});

export default router;
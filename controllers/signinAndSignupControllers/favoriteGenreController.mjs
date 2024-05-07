import express from 'express';
import User from '../../models/User.mjs'; 
import bcrypt from 'bcryptjs'; 
import jwt from 'jsonwebtoken';
import { attachCSRFToken, verifyCSRFToken } from './csrfUtils.mjs';

const router = express.Router();

router.use(attachCSRFToken);

router.get('/', (req, res) => {
    if (!req.session.fullName || !req.session.email || !req.session.otp) {
        return res.redirect('/register?errors=' + encodeURIComponent(JSON.stringify(['Session data missing. Please complete the registration process.'])));
    }

    const csrfToken = req.csrfToken;
    
    res.render('favorite-genre', { title: 'Select Your Favorite Genre', content: '', csrfToken: csrfToken});
});

router.post('/', verifyCSRFToken, async (req, res) => {
    const genresFromRequest = req.body.genre;
    req.session.selectedGenres = genresFromRequest;

    const { fullName, email, password } = req.session;

    try {
        const hashedPassword = await bcrypt.hash(password, 10); // 10 is the number of salt rounds

        // Create a new user document with session data
        const newUser = new User({
            fullName,
            email,
            password: hashedPassword,
            selectedGenres: genresFromRequest
        });

        await newUser.save();

        const token = jwt.sign({ userId: newUser._id, email: newUser.email }, process.env.SECRET, { expiresIn: '7d' });

         // Set token in response headers or cookies
         res.cookie('token', token);

        res.redirect('/');

    } catch (error) {
        console.error('Error saving user data:', error);
        // Handle error response
        res.status(500).send('Error saving user data');
    }
});

export default router;
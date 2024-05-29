import express from 'express';
import bcrypt from 'bcryptjs'; 
import jwt from 'jsonwebtoken';
import User from '../../models/User.mjs'; 
import { attachCSRFToken, verifyCSRFToken } from './csrfUtils.mjs';
import { generateToken } from './determineLoggedInStatus.mjs'
const router = express.Router();

router.use(attachCSRFToken);

router.get('/', attachCSRFToken, (req, res) => {
    const errors = req.query.errors ? JSON.parse(req.query.errors) : [];
    const csrfToken = req.csrfToken;
    res.render('signin_with_email', { title: 'Myreads Sign in', content: '', errors: errors, csrfToken: csrfToken});
});

router.post('/', verifyCSRFToken, async (req, res) => {
    const email = req.body.email;
    const password = req.body.password;
    const keepSignedIn = req.body.keepSignedIn;
    const errors = [];

    try {
        const user = await User.findOne({ email });
        if (!user) {
            errors.push("We cannot find an account with that email address");
            return res.redirect('/signin_with_email?errors=' + encodeURIComponent(JSON.stringify(errors)));
        }

        if (user.password){
            const passwordMatch = await bcrypt.compare(password, user.password);
            if (!passwordMatch) {
                errors.push("Your password is incorrect");
                return res.redirect('/signin_with_email?errors=' + encodeURIComponent(JSON.stringify(errors)));
            }
        } 

        // Authentication successful, generate JWT token
        if (keepSignedIn) {
            let tokenPayload = { userId: user._id, email: user.email };

            // Check if the user is an admin before including the isAdmin property in the token payload
            if (user.isAdmin) {
                tokenPayload.isAdmin = true;
            }
            const token = jwt.sign(tokenPayload, process.env.SECRET, { expiresIn: '7d' });
            console.log(tokenPayload)
            // Send JWT token to the client
            res.cookie('token', token, { maxAge: 7 * 24 * 60 * 60 * 1000 });
            // Set the user ID in the session
            req.session.userId = user._id;
        } else{
            // Generate a random token to sign the user in without keeping them signed in
            const signInToken = generateToken();
            req.session.signInToken = signInToken;

            // Set the user ID in the session
            req.session.userId = user._id;
        }

        res.redirect('/');
    } catch (error) {
        console.error('Error finding user:', error);
        errors.push("An unexpected error occurred. Please try again later.");
        const csrfToken = req.csrfToken;
        return res.render('signin_with_email', { errors, title: 'Myreads Sign in', content: '', csrfToken: csrfToken});
    }
});

export default router;
import express from 'express';
import User from '../../models/User.mjs'; 
import { attachCSRFToken, verifyCSRFToken } from './csrfUtils.mjs';
import { storeTokenInDatabase, sendPasswordResetEmail } from './forgotPasswordUtils.mjs';
import { generateToken } from './determineLoggedInStatus.mjs'

const router = express.Router();

router.use(attachCSRFToken);

router.get('/', (req, res) => {
    const errors = req.query.errors ? JSON.parse(req.query.errors) : [];
    const csrfToken = req.csrfToken;
    const siteKey = process.env.RECAPTCHA_SITE_KEY;
    res.render('forgot_password', { title: 'Myreads Password Assistance', content: '', errors: errors, csrfToken: csrfToken, siteKey: siteKey });
});

router.post('/', verifyCSRFToken, async (req, res) => {
    const token = req.body['g-recaptcha-response'];
    const secretKey = process.env.RECAPTCHA_SECRET;
    const email = req.body.email
    const errors = [];

    try {
        const user = await User.findOne({ email });
        if (!user) {
            errors.push("We cannot find an account with that email address");
            return res.redirect('/forgot_password?errors=' + encodeURIComponent(JSON.stringify(errors)));
        }

         const fullName = user.fullName;

        // Verify the reCAPTCHA token
        const response = await fetch(`https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${token}`, {
            method: 'POST'
        });
        const data = await response.json();

        // Check if reCAPTCHA verification was successful
        if (data.success && data.score > 0.5) {
            console.log("succesful recaptcha")
            const token_for_email = generateToken();
            await storeTokenInDatabase(email, token_for_email);

            const resetUrl = `http://localhost:3000/password_reset?token=${token_for_email}`;

            await sendPasswordResetEmail(email, resetUrl, fullName);
            res.redirect('/password_reset_email_sent');
        } else {
            console.log("failed recaptcha")
            errors.push("failed recaptch");
            return res.redirect('/forgot_password?errors=' + encodeURIComponent(JSON.stringify(errors)));
        }
    } catch (error) {
        console.error('Error processing forgot password request:', error);
        errors.push("An unexpected error occurred. Please try again later.");
        return res.redirect('/forgot_password?errors=' + encodeURIComponent(JSON.stringify(errors)));
    }
    });

    export default router;
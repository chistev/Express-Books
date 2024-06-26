import express from 'express';
import { validateEmail, generateOTP, sendEmail } from './registerUtils.mjs';
import { attachCSRFToken, verifyCSRFToken } from './csrfUtils.mjs'
import User from '../../models/User.mjs';

const router = express.Router();

router.use(attachCSRFToken);

router.get('/', (req, res) => {
    const errors = req.query.errors ? JSON.parse(req.query.errors) : [];
    const csrfToken = req.csrfToken;
    res.render('registration/register', { title: 'Myreads Registration', errors: errors, content: '', csrfToken: csrfToken });
});

router.post('/', verifyCSRFToken, async (req, res) => {
    const fullName = req.body.fullName;
    const email = req.body.email;
    const password = req.body.password;
    const reEnteredPassword = req.body['re-enter-password']; 

    const errors = [];

    if (!(fullName && fullName.trim().includes(' '))) {
        errors.push('Please enter your full name (first and last name).');
    } 

    // Check if the full name contains any numbers or is a number
    if(/\d/.test(fullName)) {
        errors.push('Full name cannot contain a number or be a number.');
    }

    if (!email || !validateEmail(email)) {
        errors.push('Please enter a valid email address.');
    }
    
    if (!password || !reEnteredPassword || password.length < 6 || password !== reEnteredPassword) {
        errors.push('Passwords must be at least 6 characters long and match.');
    }

    try {
        const existingUser = await User.findOne({ email: email });
        if (existingUser) {
            errors.push('Email address is already registered.');
        }
    } catch (error) {
        console.error('Error checking existing user:', error);
        errors.push('Error checking existing user');
    }

    if (errors.length > 0) {
        return res.redirect('/register?errors=' + encodeURIComponent(JSON.stringify(errors)));
    }

    const otp = generateOTP();
    req.session.otp = otp;
    req.session.password = password
    req.session.fullName = fullName;
    req.session.email = email;
    req.session.otpAttempts = 0;

    console.log('Session Data:', req.session);


    try {
        await sendEmail(email, fullName, otp);
        res.redirect(`/otp-request?email=${encodeURIComponent(email)}`);
    } catch (error) {
        res.status(500).send('Error sending email');
    }
});

export default router;

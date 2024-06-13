import express from 'express';
import { generateOTP } from './registerUtils.mjs';
import { attachCSRFToken, verifyCSRFToken } from './csrfUtils.mjs';

const router = express.Router();

router.use(attachCSRFToken);

const MAX_OTP_ATTEMPTS = 3;


router.get('/', (req, res) => {
    console.log('Session Data Retrieved:', req.session);
    if (!req.session.fullName || !req.session.email || !req.session.otp) {
        return res.redirect('/register?errors=' + encodeURIComponent(JSON.stringify(['Session data missing. Please complete the registration process.'])));
    }
    const csrfToken = req.csrfToken;
    const email = req.session.email; 
    const errors = req.query.errors ? JSON.parse(req.query.errors) : []; 
    const otpAttempts = req.session.otpAttempts || 0; 
    const newOTPRequest = req.session.newOTPRequest;

    // Clear the newOTPRequest flag from the session
    req.session.newOTPRequest = false;

    res.render('registration/otp-request', { title: 'Verify email address', email: email,  errors: errors, otpAttempts: otpAttempts, newOTPRequest: newOTPRequest, content: '', csrfToken: csrfToken});
});

router.post('/', verifyCSRFToken, async (req, res) => {
    const enteredOTP = req.body.otp; 
    const generatedOTP = req.session.otp;
    const fullName = req.session.fullName; 
    const email = req.session.email; 
    const otpAttempts = req.session.otpAttempts || 0;

    const errors = [];
    
    if (enteredOTP === generatedOTP) {
        return res.redirect('/favorite-genre');
    } else {
        errors.push('Invalid OTP');

        req.session.otpAttempts = otpAttempts + 1;

        if (otpAttempts >= MAX_OTP_ATTEMPTS) {
            req.session.otp = generateOTP();
            req.session.otpAttempts = 0;

            // Set flag to indicate a new OTP request has been made
            req.session.newOTPRequest = true;

            try {
                await sendEmail(email, fullName, req.session.otp);
            } catch (error) {
                res.status(500).send('Error sending email');
                return; // Return to prevent further execution
            }
        }
    }

    if (errors.length > 0 || otpAttempts >= MAX_OTP_ATTEMPTS) {
        return res.redirect('/otp-request?errors=' + encodeURIComponent(JSON.stringify(errors)));
    }
});

export default router;
import express from 'express';
import { generateOTP, sendEmail } from './registerUtils.mjs';
const router = express.Router();

router.get('/', async (req, res) => {
    const email = req.session.email;
    const fullName = req.session.fullName;

    const newOTP = generateOTP();

    // Update session with the new OTP
    req.session.otp = newOTP;
    req.session.otpAttempts = 0;

    try {
        await sendEmail(email, fullName, newOTP);
        req.session.newOTPRequest = true;
    } catch (error) {
        res.status(500).send('Error sending email');
        return;
    }

    // Redirect back to the OTP validation logic
    res.redirect('/otp-request');
});

export default router;
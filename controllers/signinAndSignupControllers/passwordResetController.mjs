import express from 'express';
import User from '../../models/User.mjs'; 
import bcrypt from 'bcryptjs'; 
import jwt from 'jsonwebtoken';

import { attachCSRFToken, verifyCSRFToken } from './csrfUtils.mjs';

const router = express.Router();

router.use(attachCSRFToken);

router.get('/', attachCSRFToken, (req, res) => {
    const csrfToken = req.csrfToken;
    const errors = req.query.errors ? JSON.parse(req.query.errors) : [];
    const token = req.query.token;
    res.render('signin/password_reset', { title: 'Myreads Password Assistance', content: '', csrfToken: csrfToken, token:token, errors: errors });
});

router.post('/', verifyCSRFToken, async (req, res) => {
    const token = req.body.token;
    const newPassword = req.body.password;
    const confirmPassword = req.body['re-enter-password'];
    const errors = []

    if (newPassword !== confirmPassword) {
        errors.push("Passwords do not match");
        return res.redirect('/password_reset?token=' + token + '&errors=' + encodeURIComponent(JSON.stringify(errors)));
    }

    try {
       const user = await User.findOne({ passwordResetToken: token });
       if (!user) {
           errors.push("Invalid or expired token");
           return res.redirect('/password_reset?token=' + token + '&errors=' + encodeURIComponent(JSON.stringify(errors)));
       }

       if (user.passwordResetTokenExpires && user.passwordResetTokenExpires < Date.now()) {
        errors.push("Your password reset token has expired, try again.");
        return res.redirect('/signin_with_email?errors=' + encodeURIComponent(JSON.stringify(errors)));
    }

       const hashedPassword = await bcrypt.hash(newPassword, 10); // 10 is the saltRounds value
       user.password = hashedPassword;
       user.passwordResetToken = undefined;
       user.passwordResetTokenExpires = undefined;
       await user.save();

        const authToken = jwt.sign({ userId: user._id, email: user.email }, process.env.SECRET, { expiresIn: '7d' });
        res.cookie('token', authToken);
        
       res.redirect('/')
       console.log("password reset successful")

    } catch (error) {
       console.error('Error resetting password:', error);
       res.status(500).json({ message: 'An unexpected error occurred' });
    }
})

export default router;
import express from 'express';
import User from '../../models/User.mjs';
import { determineLoggedInStatus } from '../signinAndSignupControllers/determineLoggedInStatus.mjs';
import { attachCSRFToken, verifyCSRFToken } from '../signinAndSignupControllers/csrfUtils.mjs';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const router = express.Router();
router.use(attachCSRFToken);

// Set up multer for file upload
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, path.join(__dirname, '../../uploads/'));
    },
    filename: function (req, file, cb) {
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});

const fileFilter = (req, file, cb) => {
    // Check if the file is an image
    if (!file.originalname.match(/\.(jpg|jpeg|png|gif)$/)) {
        return cb(new Error('Only image files are allowed!'), false);
    }
    cb(null, true);
};

const upload = multer({ 
    storage: storage,
    fileFilter: fileFilter
});

// Helper function to render account settings page
const renderAccountSettings = (res, options) => {
    res.render('account_settings/account_settings', {
        title: 'Account Settings | Myreads',
        csrfToken: options.csrfToken || '',
        activeTab: options.activeTab,
        loggedIn: options.loggedIn,
        user: options.user || null,
        content: '',
        errors: options.errors || []
    });
};

router.get('/profile', async (req, res) => {
    try {
        const { loggedIn, userId } = determineLoggedInStatus(req);
        const csrfToken = req.csrfToken || '';
        console.log(csrfToken)

        if (!loggedIn) {
            return res.redirect('/signin');
        }

        const user = await User.findById(userId).select('profilePhoto');

        if (!user) {
            return renderAccountSettings(res, {
                csrfToken,
                activeTab: 'profile',
                loggedIn,
                errors: ['User not found']
            });
        }

        renderAccountSettings(res, {
            csrfToken,
            activeTab: 'profile',
            loggedIn,
            user
        });
    } catch (error) {
        console.error('Error fetching user details:', error);
        renderAccountSettings(res, {
            csrfToken: req.csrfToken || '',
            activeTab: 'profile',
            loggedIn: determineLoggedInStatus(req).loggedIn,
            errors: ['Internal Server Error']
        });
    }
});

router.get('/settings', async (req, res) => {
    try {
        const { loggedIn, userId } = determineLoggedInStatus(req);
        const csrfToken = req.csrfToken;

        if (!loggedIn) {
            return res.redirect('/signin');
        }

        const user = await User.findById(userId).select('email');

        if (!user) {
            return renderAccountSettings(res, {
                csrfToken,
                activeTab: 'settings',
                loggedIn,
                errors: ['User not found']
            });
        }

        renderAccountSettings(res, {
            csrfToken,
            activeTab: 'settings',
            loggedIn,
            user
        });
    } catch (error) {
        console.error('Error fetching user details:', error);
        renderAccountSettings(res, {
            csrfToken: req.csrfToken || '',
            activeTab: 'settings',
            loggedIn: determineLoggedInStatus(req).loggedIn,
            errors: ['Internal Server Error']
        });
    }
});

router.post('/upload_profile_photo', upload.single('profilePhoto'), async (req, res) => {
    console.log('POST /upload_profile_photo hit');
    try {
        const { loggedIn, userId } = determineLoggedInStatus(req);
        console.log('Logged in status:', loggedIn, 'User ID:', userId);
        if (!loggedIn) {
            return res.redirect('/signin');
        }

        const user = await User.findById(userId);
        console.log('User found:', user);

        if (!user) {
            console.log('User not found');
            return renderAccountSettings(res, {
                csrfToken: req.csrfToken || '',
                activeTab: 'profile',
                loggedIn,
                errors: ['User not found']
            });
        }

        if (!req.file) {
            console.log('No file uploaded');
            return renderAccountSettings(res, {
                csrfToken: req.csrfToken || '',
                activeTab: 'profile',
                loggedIn,
                user,
                errors: ['No file uploaded']
            });
        }

        console.log('File uploaded:', req.file);

        user.profilePhoto = `/uploads/${req.file.filename}`;
        await user.save();
        console.log('Profile photo updated successfully:', user);

        res.redirect('/account_settings');
    } catch (error) {
        console.error('Error uploading profile photo:', error);
        renderAccountSettings(res, {
            csrfToken: req.csrfToken || '',
            activeTab: 'profile',
            loggedIn,
            errors: ['Internal Server Error']
        });
    }
});

export default router;

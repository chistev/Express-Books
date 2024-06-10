import express from 'express';
import sanitizeHtml from 'sanitize-html';
import Book from '../../models/Book.mjs';
import { isAdmin } from './isAdmin.mjs'
import { upload } from '../multerConfig.mjs'
import { attachCSRFToken, verifyCSRFToken } from '../signinAndSignupControllers/csrfUtils.mjs'

const router = express.Router();

router.use(attachCSRFToken);

router.get('/admin', async (req, res) => {
    res.redirect('/admin/add_book');
});


router.get('/admin/add_book', isAdmin, async (req, res) => {
    const errors = req.query.errors ? JSON.parse(req.query.errors) : [];
    const csrfToken = req.csrfToken;
    res.render('admin/add_book', { title: 'admin', errors: errors, content: '', csrfToken: csrfToken });
});

router.post('/admin/add_book', verifyCSRFToken, upload.single('image'), async (req, res) => {
    const errors = [];
    const { title, author, description, genre, pages, mediaType, publishedDate } = req.body;
    const imagePath = `/uploads/${req.file.filename}`;

    const sanitizedDescription = sanitizeHtml(description, {
        allowedTags: sanitizeHtml.defaults.allowedTags.concat(['h1', 'h2', 'img']),
        allowedAttributes: {
            a: ['href', 'name', 'target'],
            img: ['src', 'alt'],
            '*': ['style', 'class']
        }
    });

    let parsedPages = null;
    if (pages && pages.trim() !== '') {
        parsedPages = parseInt(pages, 10);
    }

    const newBook = new Book({
        image: imagePath,
        title,
        author,
        description: sanitizedDescription,
        genre: Array.isArray(genre) ? genre : [genre],
        pages: parsedPages,
        mediaType,
        publishedDate: new Date(publishedDate)
    });

    await newBook.save();
    console.log('Book created successfully:', newBook);
    res.redirect('/');
});

export default router;

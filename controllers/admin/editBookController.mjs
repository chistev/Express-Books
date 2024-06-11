import express from 'express';
import { isAdmin } from './isAdmin.mjs';
import { upload } from '../multerConfig.mjs';
import { attachCSRFToken, verifyCSRFToken } from '../signinAndSignupControllers/csrfUtils.mjs';
import Book from '../../models/Book.mjs';

const router = express.Router();

router.use(attachCSRFToken);

router.get('/admin/edit_book/:id', isAdmin, async (req, res) => {
    try {
        const book = await Book.findById(req.params.id);
        if (!book) {
            return res.status(404).send('Book not found');
        }
        const errors = req.query.errors ? JSON.parse(req.query.errors) : [];
        const csrfToken = req.csrfToken;
        res.render('admin/edit_book_form', { title: 'Edit Book', book, errors, csrfToken, content: '' });
    } catch (error) {
        console.error('Error fetching book:', error);
        res.status(500).send('Internal Server Error');
    }
});

router.post('/admin/update_book/:id', upload.single('image'), verifyCSRFToken, async (req, res) => {
    try {
        const { title, author, description, genre, pages, mediaType, publishedDate } = req.body;
        const book = await Book.findById(req.params.id);

        if (!book) {
            return res.status(404).send('Book not found');
        }

        book.title = title;
        book.author = author;
        book.description = description;
        book.genre = Array.isArray(genre) ? genre : [genre];
        if (pages) {
            book.pages = parseInt(pages, 10);
        }
        book.mediaType = mediaType;
        book.publishedDate = new Date(publishedDate);

        if (req.file) {
            book.image = `/uploads/${req.file.filename}`;
        }

        await book.save();
        console.log('Book updated successfully:', book);
        res.redirect('/admin/edit_book');
    } catch (error) {
        console.error('Error updating book:', error);
        res.status(500).send('Internal Server Error');
    }
});

export default router;

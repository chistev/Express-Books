import express from 'express';
import Book from '../../models/Book.mjs';
import { isAdmin } from './isAdmin.mjs'
import { attachCSRFToken, verifyCSRFToken } from '../signinAndSignupControllers/csrfUtils.mjs'

const router = express.Router();

router.use(attachCSRFToken);

router.get('/admin/delete_book', isAdmin, async (req, res) => {
    try {
        const books = await Book.find({});
        const csrfToken = req.csrfToken;
        res.render('admin/delete_book', { title: 'Delete Book', books, csrfToken, content:''});
    } catch (error) {
        console.error('Error fetching books:', error);
        res.status(500).send('Internal Server Error');
    }
});

router.post('/admin/delete_book/:id', verifyCSRFToken, async (req, res) => {
    try {
        const book = await Book.findByIdAndDelete(req.params.id);
        if (!book) {
            return res.status(404).send('Book not found');
        }
        console.log('Book deleted successfully:', book);
        res.redirect('/admin/delete_book');
    } catch (error) {
        console.error('Error deleting book:', error);
        res.status(500).send('Internal Server Error');
    }
});

export default router;
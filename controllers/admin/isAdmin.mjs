import jwt from 'jsonwebtoken';

export const isAdmin = (req, res, next) => {
    const token = req.cookies.token;

    if (!token) {
        return res.redirect('/signin_with_email?errors=' + encodeURIComponent(JSON.stringify(['Unauthorized'])));
    }

    try {
        const decoded = jwt.verify(token, process.env.SECRET);

        if (decoded && decoded.isAdmin) {
            next();
        } else {
            return res.redirect('/signin_with_email?errors=' + encodeURIComponent(JSON.stringify(['Forbidden'])));
        }
    } catch (error) {
        console.error('Error verifying JWT token:', error);
        return res.redirect('/signin_with_email?errors=' + encodeURIComponent(JSON.stringify(['Internal Server Error'])));
    }
};

import jwt from 'jsonwebtoken';

export function authenticateToken(req, res, next) {
    const token = req.cookies.token || req.session.signInToken;
    if (!token) return res.status(401).send('Access Denied');

    try {
        const verified = jwt.verify(token, process.env.SECRET);
        req.userId = verified.id;
        next();
    } catch (err) {
        res.status(400).send('Invalid Token');
    }
}

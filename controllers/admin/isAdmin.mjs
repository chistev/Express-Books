import jwt from 'jsonwebtoken';

export const isAdmin = (req, res, next) => {
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    try {
        const decoded = jwt.verify(token, process.env.SECRET);

        if (decoded && decoded.isAdmin) {
            next();
        } else {
            return res.status(403).json({ message: 'Forbidden' });
        }
    } catch (error) {
        console.error('Error verifying JWT token:', error);
        return res.status(500).json({ message: 'Internal Server Error' });
    }
};

const db = require('../services/database.service');

const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ success: false, message: 'Access denied: No token provided' });

    try {
        // Check session in database
        const session = await db.getSession(token);

        if (!session) {
            return res.status(403).json({ success: false, message: 'Invalid session' });
        }

        // Check expiration if applicable (optional dependent on existing logic, but good practice)
        if (session.expires_at && new Date(session.expires_at) < new Date()) {
            await db.deleteSession(token);
            return res.status(403).json({ success: false, message: 'Session expired' });
        }

        // Get fresh user data
        const user = await db.getUserById(session.user_id);
        if (!user) {
            return res.status(403).json({ success: false, message: 'User not found' });
        }

        req.user = user;
        req.token = token; // Pass token just in case
        next();
    } catch (err) {
        console.error('Auth error:', err);
        return res.status(500).json({ success: false, message: 'Internal server error during auth' });
    }
};

const requireAdmin = (req, res, next) => {
    if (!req.user || (req.user.is_admin !== 1 && req.user.is_admin !== true)) {
        return res.status(403).json({ 
            success: false, 
            error: 'Quyền quản trị viên là bắt buộc',
            message: 'Admin access required' 
        });
    }
    next();
};

module.exports = { authenticateToken, requireAdmin };

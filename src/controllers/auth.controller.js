import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import db from '../models/index.js'; // Assuming Sequelize models are set up in index.js

const users = []; // In-memory user store (replace with DB in production)
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';

/**
 * @swagger
 * tags:
 *   - name: Auth
 *     description: Authentication routes
 */


/**
 * @swagger
 * /auth/register:
 *   post:
 *     summary: Register a new user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [name, email, password]
 *             properties:
 *               name: { type: string }
 *               email: { type: string, format: email }
 *               password: { type: string }
 *     responses:
 *       201: { description: Registered }
 *       400: { description: Email already registered }
 */

// POST /register

export const register = async (req, res) => {
    try {
        // Hash password before saving
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        
        const user = await db.User.create({
            ...req.body,
            password: hashedPassword
        });
        
        res.status(201).json({
            message: "User registered",
            user: {
                id: user.id,
                email: user.email
            }
        });
    } catch (err) {
        if (err.name === 'SequelizeUniqueConstraintError') {
            return res.status(400).json({ error: 'Email already registered' });
        }
        res.status(500).json({ error: err.message });
    }
};

/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: Login a user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password]
 *             properties:
 *               email: { type: string , format: email }
 *               password: { type: string }
 *     responses:
 *       200: { description: successfull login }
 *       400: { description: Invalid credentials }
 *       404: { description: User not found }
 */

// POST /login
export const login = async (req, res) => {
    const { email, password } = req.body;
    
    try {
        // Find user in database instead of memory array
        const user = await db.User.findOne({ where: { email } });
        
        if (!user) {
            console.log(`User not found for email: ${email}`);
            return res.status(404).json({ error: 'User not found' });
        }

        console.log(`Comparing password for user: ${user.email}`);
        const valid = await bcrypt.compare(password, user.password);
        
        if (!valid) {
            console.log(`Password comparison failed for user: ${user.email}`);
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        // Generate and return token
        const token = jwt.sign(
            { id: user.id, email: user.email, name: user.name },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({
            token,
            user: {
                id: user.id,
                email: user.email,
                name: user.name
            }
        });
        
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
};



/**
 * @swagger
 * /auth/users:
 *   get:
 *     summary: Get all users (protected)
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200: { description: List of users }
 *       401: { description: Unauthorized }
 */

// GET /users (protected)
export const getUsers = async (req, res) => {
    try {
        const users = await db.User.findAll({
            attributes: ['id', 'name', 'email'] // Don't return passwords
        });
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};
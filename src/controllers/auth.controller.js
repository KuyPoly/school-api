import bcrypt from 'bcryptjs';
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import db from '../models/index.js';

dotenv.config();
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
 *             required:
 *               - name
 *               - email
 *               - password
 *             properties:
 *               name:
 *                 type: string
 *               email:
 *                 type: string 
 *                 format: email
 *               password:
 *                 type: string
 *     responses:
 *       201:
 *         description: User registered successfully
 *       400:
 *         description: All fields are required or user already exists
 *       500:
 *         description: Server error
 */
export const register = async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ message: 'All fields are required' });
        }
        const existingUser = await db.Student.findOne({ where: { email } });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await db.Student.create({ name, email, password: hashedPassword });
        res.status(201).json({ message: 'User registered successfully', data: newUser });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
}

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
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string 
 *                 format: email
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                 token:
 *                   type: string
 *       400:
 *         description: Email and password are required
 *       401:
 *         description: Invalid credentials
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error
 */
export const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }
        const user = await db.Student.findOne({ where: { email } });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        const jwtSecretKey = process.env.JWT_SECRET;
        const token = jwt.sign({ id: user.id, email: user.email }, jwtSecretKey, { expiresIn: '1h' });
        res.status(200).json({ message: 'Login successful', token });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
}
/**
 * Middleware to authenticate JWT token from the Authorization header.
 *
 * @function authenticateToken
 * @param {import('express').Request} req - Express request object.
 * @param {import('express').Response} res - Express response object.
 * @param {import('express').NextFunction} next - Express next middleware function.
 * @returns {void}
 * @description
 * Checks for a Bearer token in the Authorization header. If present and valid, attaches the decoded user to req.user and calls next().
 * If missing, responds with 401. If invalid, responds with 403.
 */
export const authenticateToken = (req, res, next) => {
    // Read Authorization header
    const authHeader = req.headers['authorization'];
    
    if (!authHeader) {
        console.log("Authorization Header:", authHeader);
        return res.status(401).json({ message: "Access Denied. No token provided." });
    }

    // Extract token from "Bearer <token>"
    const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : authHeader;

    const jwtSecretKey = process.env.JWT_SECRET;

    try {
        // Verify token
        const decoded = jwt.verify(token, jwtSecretKey);
        req.user = decoded;  // Attach decoded user info to req
        next();  // Allow request to continue
    } catch (error) {
        return res.status(403).json({ message: "Access Denied. Invalid token." });
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
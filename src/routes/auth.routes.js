import express from 'express';
import { register, login, getUsers } from '../controllers/auth.controller.js';
import { jwtMiddleware } from '../middleware/jwt.middleware.js';

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.get('/users', jwtMiddleware, getUsers);

export default router;
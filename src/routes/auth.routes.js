import {register, login} from '../controllers/auth.controller.js';
import router from 'express';

const authRouter = router();
// Register route
authRouter.post('/register', register);
// Login route
authRouter.post('/login', login);
export default authRouter;
import express from 'express';
import dotenv from 'dotenv';
import studentRoutes from './routes/student.routes.js';
import courseRoutes from './routes/course.routes.js';
import teacherRoutes from './routes/teacher.routes.js';
import { serveSwagger, setupSwagger } from './config/swagger.js';
import jwt from 'jsonwebtoken';
import authRouter from './routes/auth.routes.js';
import { authenticateToken } from './controllers/auth.controller.js';
dotenv.config();



const app = express();
const PORT = process.env.PORT || 3000;
app.use(express.json());

app.use('/docs', serveSwagger, setupSwagger);
app.use('/auth', authRouter);


app.use('/students', authenticateToken, studentRoutes);
app.use('/courses' , authenticateToken, courseRoutes);
app.use('/teachers', authenticateToken, teacherRoutes);

app.get('/', (req, res) => res.send('Welcome to School API!'));

app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
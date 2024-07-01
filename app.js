import express from 'express';
import userRouter from './Routers/userRoutes.js';
import authRouter from  './Routers/authRoutes.js';
import { isAdmin, verifyJWT } from './Controllers/AuthController.js';

const app = express();

app.use(express.json());

app.use('/', (req, res, next) => {
    console.log('Got Hit🎉');
    next();
})
app.use('/api/v1/users', verifyJWT, isAdmin, userRouter);
app.use('/api/v1/auth', authRouter)

export default app;
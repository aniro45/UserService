import express from 'express';
import { createMultipleUsers, createUser, getAllUsers } from '../Controllers/userController.js';
import { isAdmin } from '../Controllers/AuthController.js';

const router = express.Router();

router.get('/', getAllUsers);
router.post('/', isAdmin, createUser);
router.post('/multi', isAdmin, createMultipleUsers);


export default router;
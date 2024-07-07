import express from "express";
import {
    authenticateUser,
    deleteProfile,
    login,
    logout,
    signup,
    modifyProfile,
    verifyJWT,
    getProfile,
    makeUserVerified,
    isUserVerified,
} from "../Controllers/AuthController.js";

const router = express.Router();

router.post("/signup", signup);
router.get("/email_verification", makeUserVerified);
router.post("/login", authenticateUser, isUserVerified, login);
router.post("/logout", verifyJWT, logout);
router.patch("/patchProfile", verifyJWT, modifyProfile);
router.delete("/deleteUser", verifyJWT, deleteProfile);
router.get("/user", verifyJWT, getProfile);

export default router;

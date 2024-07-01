import User from "../Models/userModel.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { userRoles } from "../constants.js";

export function isAdmin(req, res, next) {
    if (req.user.role === userRoles.ADMIN) {
        next();
    } else {
        res.status(401).json({
            status: "FAILED",
            message: "This is admin restricted API.",
        });
    }
}

export function logout(req, res, next) {
    try {
        const { exp, ...restUserData } = req?.user;
        const token = generateTokenWithImmediateExpiry(restUserData);
        res.cookie("authToken", token, { httpOnly: true });
        res.status(200).json({
            status: "SUCCESS",
            message: `Logged out successfully`,
        });
    } catch (error) {
        res.status(200).json({
            status: "FAILED",
            message: `Problem while Logging out! Try Again.`,
            error: error,
        });
    }
}

export async function authenticateUser(req, res, next) {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ where: { email: email } });
        if (user) {
            bcrypt.compare(password, user.password, (err, result) => {
                if (err) {
                    res.status(501).json({
                        status: "FAILED",
                        message: "Error while comparing password",
                        error: err,
                    });
                } else if (result) {
                    req.user = user;
                    next();
                } else {
                    res.status(501).json({
                        status: "FAILED",
                        message: "wrong password",
                        error: err,
                    });
                }
            });
        } else {
            res.status(401).json({
                status: "FAILED",
                message: "user id or password is wrong",
                error: error,
            });
        }
    } catch (error) {
        res.status(401).json({
            status: "FAILED",
            message: "login Failed",
            error: error,
        });
    }
}

export async function login(req, res, next) {
    try {
        const { id, role, email } = req.user;
        const token = await generateJWT({
            sub: id,
            role: role,
        });
        res.cookie("authToken", token, { httpOnly: true });
        res.status(200).json({
            status: "SUCCESS",
            message: `Logged in successful as ${email}`,
        });
    } catch (error) {
        res.status(501).json({
            status: "FAILED",
            message: "Problem while logging in",
            error: error,
        });
    }
}

export async function sendMailWithVerificationLink(URL, email) {

}

export async function signup(req, res, next) {
    const body = req.body;
    try {
        const hashedPassword = await hashPassword(body.password);
        const user = await User.build({
            ...body,
            password: hashedPassword,
        });
        user.save();
        const { id, role } = user
        const token = generateJWTForVerification({sub: id, role: role});
        const URL = generateAccountVerificationURL(token);
        sendMailWithVerificationLink(URL, user.email) //TODO: add code for send email
        res.status(201).json({
            status: "SUCCESS",
            message: "Account created successfully.",
            data: user,
        });
    } catch (error) {
        res.status(501).json({
            status: "FAILED",
            message: "Problem while signing up",
            error: error,
        });
    }
}

export async function modifyProfile(req, res) {
    const id = req.user.sub;
    const user = await User.findOne({ where: { id: id } });
    if (req.body.firstName) user.firstName = req.body.firstName;
    if (req.body.lastName) user.lastName = req.body.lastName;
    if (req.body.dateOfBirth) user.dateOfBirth = req.body.dateOfBirth;
    user.save();
    res.status(200).json({
        status: "SUCCESS",
        message: "Users details updated successfully",
        data: user,
    });
}

export async function deleteProfile(req, res) {
    const id = req.user.sub;
    const user = await User.findOne({ where: { id: id } });
    user.destroy();
    const { exp, ...restUserData } = req.user;
    const token = generateTokenWithImmediateExpiry(restUserData);
    res.cookie("authToken", token, { httpOnly: true });
    res.status(200).json({
        status: "SUCCESS",
        message: "Users deleted Success",
        data: {},
    });
}

export async function makeUserVerified(req, res) {
    try {
        const token = req.param.token;
        const jwtSecretKey = process.env.JWT_SECRET_KEY;
        jwt.verify(token, jwtSecretKey, (err, payload) => {
            if (err) {
                res.status(401).send({
                    status: "FAIL",
                    message: "Could not verify the link",
                    error: err,
                });
                return;
            }
            const user = User.findOne({ where: { id: payload.sub } });
            user.verifiedEmail = true;
            user.save();
            res.status(200).json({
                status: "SUCCESS",
                message: "Email has been verified successfully",
            });
        });
    } catch (error) {
        res.status(501).json({
            status: "FAILED",
            message: "Problem while email verification",
            error: error,
        });
    }
}

async function generateJWT(data) {
    const jwtSecretKey = process.env.JWT_SECRET_KEY;
    const token = jwt.sign(data, jwtSecretKey, {
        expiresIn: process.env.JWT_TOKEN_EXPIRY_DURATION,
        algorithm: "HS256",
    });
    return token;
}

async function generateJWTForVerification(data) {
    const jwtSecretKey = process.env.JWT_SECRET_KEY;
    const token = jwt.sign(data, jwtSecretKey, {
        expiresIn: process.env.JWT_TOKEN_FOR_VERIFICATION_DURATION,
        algorithm: "HS256",
    });
    return token;
}

async function generateTokenWithImmediateExpiry(data) {
    const jwtSecretKey = process.env.JWT_SECRET_KEY;
    const token = jwt.sign(data, jwtSecretKey, {
        expiresIn: process.env.JWT_TOKEN_FORCE_EXPIRY_DURATION,
    });
    return token;
}

async function generateAccountVerificationURL(token) {
    const URL = `http://localhost:5560/api/v1/email_verification/?token=${token}`;
    return URL;
}


export async function verifyJWT(req, res, next) {
    try {
        const jwtSecretKey = process.env.JWT_SECRET_KEY;
        const { cookie } = req.headers;
        const token = cookie && getAuthTokenFromCookie(cookie);
        jwt.verify(token, jwtSecretKey, (err, user) => {
            if (err) {
                res.status(401).send({
                    status: "FAIL",
                    message: "Access Denied. Token verification failed",
                    error: err,
                });
                return;
            }
            req.user = user;
            next();
        });
    } catch (error) {
        res.status(501).json({
            status: "SUCCESS",
            message: "Problem while verifying the token",
            error: error,
        });
    }
}

function getAuthTokenFromCookie(cookieValue) {
    return cookieValue.split("=")[1];
}

export async function getProfile(req, res, next) {
    try {
        const user = await User.findOne({ where: { id: req.user.sub } });
        res.status(200).json({
            status: "SUCCESS",
            message: "User fetched successfully",
            data: user,
        });
    } catch (error) {
        res.status(501).json({
            status: "FAILED",
            message: "Problem while fetching the user",
            error: error,
        });
    }
}

export function hashPassword(plainPassword) {
    const saltRounds = 10;
    const hashedPassword = bcrypt.hash(plainPassword, saltRounds);
    return hashedPassword;
}

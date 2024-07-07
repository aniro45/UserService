import User from "../Models/userModel.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { userRoles } from "../constants.js";
import axios from "axios";
import { getHTMLForEmailVerification } from "../templates/emailTemplates.js";

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

export async function sendMailWithVerificationLink(
    verificationURL,
    toEmail,
    firstName,
) {
    try {
        const EMAIL_SERVICE_ENDPOINT_FOR_SEND = `http://localhost:5570/api/v1/email/sendEmail?key=${process.env.EMAIL_SERVICE_API_KEY}`;
        const html = getHTMLForEmailVerification(firstName, verificationURL);
        const result = await axios.post(EMAIL_SERVICE_ENDPOINT_FOR_SEND, {
            to: toEmail,
            from: process.env.FROM_EMAIL_ADDRESS,
            subject: `Verify your email`,
            html: html,
        });

        if (result.data.status !== "FAILED") {
            console.log("Email sent successfully!");
        } else {
            console.log("FAILED sending email");
        }
    } catch (error) {
        console.log(`problem while sending the email \n Error:${error}`);
    }
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
        const { id, role } = user;
        const token = await generateJWTForVerification({ sub: id, role: role });
        const verificationURL = generateAccountVerificationURL(token);
        sendMailWithVerificationLink(
            verificationURL,
            user.email,
            user.firstName,
        );
        res.status(201).json({
            status: "SUCCESS",
            message:
                "Account created successfully. Please verify your email before proceed",
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
        const token = req.query.token;
        const jwtSecretKey = process.env.JWT_SECRET_KEY;
        jwt.verify(token, jwtSecretKey, async (err, payload) => {
            if (err) {
                res.status(401).send({
                    status: "FAIL",
                    message: "Could not verify the link",
                    error: err,
                });
                return;
            }
            const user = await User.findOne({ where: { id: payload.sub } });
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

function generateAccountVerificationURL(token) {
    const URL = `http://localhost:5560/api/v1/auth/email_verification/?token=${token}`;
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

export async function isUserVerified(req, res, next) {
    try {
        const user = await User.findOne({ where: { id: req.user.id } });
        if (!user.verifiedEmail) {
            return res.status(403).json({
                status: "FAILED",
                message: "User is not verified. Please verify the user first",
            });
        }
        next();
    } catch (error) {
        res.status(501).json({
            status: "FAILED",
            message: "problem while logging in",
            error: error,
        });
    }
}

export function hashPassword(plainPassword) {
    const saltRounds = 10;
    const hashedPassword = bcrypt.hash(plainPassword, saltRounds);
    return hashedPassword;
}

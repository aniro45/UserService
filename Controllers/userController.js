import { where } from "sequelize";
import User from "../Models/userModel.js";
import { hashPassword } from "./AuthController.js";

export async function createUser(req, res) {
    try {
        const body = req.body;
        const user = await User.create(body);
        res.status(201).json({
            status: "SUCCESS",
            message: "Users created successfully",
            data: user,
        });
    } catch (error) {
        res.status(501).json({
            status: "FAILED",
            message: "Problem while creating user",
            error: error?.errors[0]?.message,
        });
    }
}

export async function createMultipleUsers(req, res, next) {
    try {
        const bodies = req.body;
        const users = [];

        for (let body of bodies) {
            try {
                const hashedPassword = await hashPassword(body.password);
                const user = await User.build({
                    ...body,
                    password: hashedPassword,
                });
                user.save();
                users.push(user);
            } catch (error) {
                res.status(501).json({
                    status: "FAILED",
                    message: "Problem while signing up",
                    error: error,
                });
            }
        }
        res.status(201).json({
            status: "SUCCESS",
            message: "Multiple Accounts created successfully.",
            data: users,
        });
    } catch (error) {
        res.status(501).json({
            status: "FAILED",
            message: "Problems while creating multiple users",
            error: error,
        });
    }
}

export async function getAllUsers(req, res) {
    const dbRes = await User.findAll();
    res.status(200).json({
        status: "SUCCESS",
        message: "Users fetched successfully",
        data: dbRes,
    });
}

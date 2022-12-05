import { Request, Response } from "express";
import bcrypt from "bcrypt";
import { successResponse, errorResponse, handleError } from "../utils/responses";
import models from "../models";
import { IUser, IOtp } from "../utils/interface";
import sendEmail from "../utils/email";
import jwtHelper from "../utils/jwt";

const { generateToken} = jwtHelper
/**
 * @class UserController
 * @description create, log in user
 * @exports UserController
 */
 export default class UserController {
    /**
     * @param {object} req - The reset request object
     * @param {object} res - The reset errorResponse object
     * @returns {object} Success message
     */
static async createUser(req: Request, res: Response) {
    try {
        const { 
            firstName, lastName, phone, email, password
        } = req.body;
        const emailExists = await models.User.findOne({ email});
        if (emailExists) {
            return  errorResponse ( res, 409 , "email aalready exists");
        }
        const phoneExists = await models.User.findOne({ phone })
        if (phoneExists) {
            return errorResponse (res, 409, "Phone number already in use")
        }
        const hashedPassword = await bcrypt.hash(password, 10)
        await models.User.create({firstName, lastName, phone, email, password : hashedPassword})
        const otp = `${Math.floor(10000 + Math.random() * 90000)};`
        await models.Otp.create({email, token : otp});
        const subject = "user created"
        const message = "hi, thank you for signing up kindly verify your account with the token  ${otp}";
        await sendEmail(email, subject , message);
        return successResponse(res, 201, "Account created successfully kindly verify your email and login");
    } catch (error) {
        handleError(error, req);
        return errorResponse(res, 500, "server error");
    }
}
 /**
   * @param {object} req - The reset request object
   * @param {object} res - The reset errorResponse object
   * @returns {object} Success message
   */
  static async loginUser(req: Request, res: Response) {
    try{
    const { email, password } = req.body;
    const user: IUser | null = await models.User.findOne({email})
    if (!user) {return errorResponse (res, 409, "email does not exist")};
    if (!user.verified) {
        return errorResponse( res, 409, "kindly verify your account")
    }
    if (user.active ==!true) {
        return errorResponse (res, 403, "This account has been deactivated, kindly contact admin for further assistance");
    }
    const validatePassword = await bcrypt.compare(password, user.password);
    if (!validatePassword) {
        return errorResponse( res, 404, "Password incorrect, try again");
    }
    const {_id, phone} = user;
    const token = await generateToken({_id, email, phone});
    if (user.active !== true) {
        return errorResponse(res, 403, "User account is inactive, contact admin");
    };
    const userDetails = {
        _id, email, firstName:user.firstName, lastName: user.lastName, phome: user.phone, role: user.role,  photo: user.photo, active: user.active
    };
    return successResponse(
        res,
        200,
        "User succesfully logged in",
         { token, userDetails }
    );
    } catch (error) {
        handleError(error, req);
        return errorResponse( res, 500, "server error")
    }
}
 }
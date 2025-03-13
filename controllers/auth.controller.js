import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

import User from "../models/user.model.js";
import { JWT_SECRET, JWT_EXPIRES_IN } from "../config/env.js";

export const signUp = async (req, res, next) => {
  const session = await mongoose.startSession(); // all or nothing
  session.startTransaction();

  try {
    const { name, email, password } = req.body;

    // Check if a user already exists
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      const error = new Error("User already exists");
      error.statusCode = 409;
      throw error;
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUsers = await User.create(
      [{ name, email, password: hashedPassword }],
      { session }
    );

    const token = jwt.sign({ userId: newUsers[0]._id }, JWT_SECRET, {
      expiresIn: JWT_EXPIRES_IN,
    });

    await session.commitTransaction(); // 提交tx 数据生效
    session.endSession();

    res.status(201).json({
      success: true,
      message: "User created successfully",
      data: {
        token,
        user: newUsers[0],
      },
    });
  } catch (error) {
    await session.abortTransaction(); // 如果有问题 终止tx 所有数据不动
    session.endSession();
    next(error);
  }
};

export const signIn = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      const error = new Error("User not found");
      error.statusCode = 404;
      throw error;
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      const error = new Error("Invalid password");
      error.statusCode = 401;
      throw error;
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, {
      expiresIn: JWT_EXPIRES_IN,
    });

    res.status(200).json({
      success: true,
      message: "User signed in successfully",
      data: {
        token,
        user,
      },
    });
  } catch (error) {
    next(error);
  }
};

export const signOut = async (req, res, next) => {};

// {
//   "success": true,
//   "message": "User created successfully",
//   "data": {
//     "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2N2QyYWM4MTM3ZjgyMmVlNWNjOGJkYjYiLCJpYXQiOjE3NDE4NTk5NjksImV4cCI6MTc0MTk0NjM2OX0.Cd05unsXXQ_Kg1uolg9cL1GoASl4TQ-uMl1Spc3y_zw",
//     "user": {
//       "name": "aa",
//       "email": "e@q.com",
//       "password": "$2a$10$rhmQNrew.YF0.GUcST6ujOVJ6sCW2fvjE6/3umlePz9UlmkgRSsb6",
//       "_id": "67d2ac8137f822ee5cc8bdb6",
//       "createdAt": "2025-03-13T09:59:29.547Z",
//       "updatedAt": "2025-03-13T09:59:29.547Z",
//       "__v": 0
//     }
//   }
// }

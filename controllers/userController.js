import UserModel from "../models/User.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import transporter from "../config/emailConfig.js";

class UserController {
  static userRegistration = async (req, res) => {
    try {
      const { name, email, password, tc } = req.body;

      if (!(name && email && password && tc)) {
        res.status(400).send("All fields are required.");
      }

      const oldUser = await UserModel.findOne({ email: email });

      if (oldUser) {
        return res.status(409).send("Email already exists.");
      }

      const hashPassword = await bcrypt.hash(password, 10);

      const doc = new UserModel({
        name: name,
        email: email,
        password: hashPassword,
        tc: tc,
      });
      await doc.save();
      const saved_user = await UserModel.findOne({ email: email });

      // Generate jwt token
      const token = jwt.sign(
        { userID: saved_user._id },
        process.env.JWT_SECRET_KEY,
        { expiresIn: "5d" }
      );
      res.status(201).send({ message: "User Created!" });
    } catch (error) {
      console.log(error);
    }
  };

  static userLogin = async (req, res) => {
    try {
      const { email, password } = req.body;

      if (!(email && password)) {
        res.status(400).send("All fields are required.");
      }
      const oldUser = await UserModel.findOne({ email: email });
      if (oldUser != null) {
        const isMatch = await bcrypt.compare(password, oldUser.password);
        if (oldUser.email === email && isMatch) {
          // Generate jwt token
          const token = jwt.sign(
            { userID: oldUser._id },
            process.env.JWT_SECRET_KEY,
            { expiresIn: "5d" }
          );
          res.status(200).send({ message: "Login Successful!", token: token });
          return;
        } else {
          res.status(400).send("Invalid credentials");
        }
      } else {
        res.status(400).send("User with this email isn't registered.");
      }
    } catch (error) {
      console.log(error);
      res.status(500).send("Internal server error");
    }
  };

  static changeUserPassword = async (req, res) => {
    const { password } = req.body;
    if (password) {
      const newHashPassword = await bcrypt.hash(password, 10);
      await UserModel.findByIdAndUpdate(req.user._id, {
        $set: { password: newHashPassword },
      });
      res.status(200).send("Password changed successfully.");
    } else {
      res.status(404).send("Password is required.");
    }
  };

  static loggedUser = async (req, res) => {
    res.send({ User: req.user });
  };

  static sendUserPasswordResetEmail = async (req, res) => {
    const { email } = req.body;
    if (email) {
      const user = await UserModel.findOne({ email: email });
      if (user) {
        const secret = user._id + process.env.JWT_SECRET_KEY;
        const token = jwt.sign({ userID: user._id }, secret, {
          expiresIn: "15m",
        });
        // For frontend
        const link = `http://localhost:3000/api/user/reset/${user._id}/${token}`;
        console.log(link);

        // Send Email
        let info = await transporter.sendMail({
          from: process.env.EMAIL_FROM,
          to: user.email,
          subject: "BushShop - Password Reset Link",
          html: `<a href=${link}>Click Here</a> to Reset Your Password`,
        });
        res.status(200).send({
          message: "Password reset email sent..Please check your email.",
          info: info,
        });
      } else {
        res.status(400).send("Email doesn't exists.");
      }
    } else {
      res.status(400).send("Email field is required.");
    }
  };

  static userPasswordReset = async (req, res) => {
    const { password, password_confirmation } = req.body;
    const { id, token } = req.params;
    const user = await UserModel.findById(id);
    const new_secret = user._id + process.env.JWT_SECRET_KEY;
    try {
      jwt.verify(token, new_secret);
      if (password && password_confirmation) {
        if (password !== password_confirmation) {
          res.status(400).send("Password and confirm password doesn't match.");
        } else {
          const newHashPassword = await bcrypt.hash(password, 10);
          await UserModel.findByIdAndUpdate(user._id, {
            $set: { password: newHashPassword },
          });
          res.status(200).send("Password reset successfully.");
        }
      }
    } catch (error) {
      console.log(error);
      res.status(400).send({ message: "Invalid Token" });
    }
  };
}

export default UserController;

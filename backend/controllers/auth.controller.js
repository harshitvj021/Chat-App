import bcryptjs from "bcryptjs";
import User from "../models/user.model.js";
import generateTokenAndSetCookie from "../utils/generateToken.js";

export const signup = async (req, res) => {
  try {
    const { fullName, username, password, confirmPassword, gender } = req.body;

    if (password !== confirmPassword) {
      return res.status(400).json({ error: "Passwords don't match" });
    }

    const existingUser = await User.findOne({ username });

    if (existingUser) {
      return res.status(400).json({ error: "Username already exists" });
    }

    // Hash the password
    const salt = await bcryptjs.genSalt(10);
    const hashedPassword = await bcryptjs.hash(password, salt);

    // Determine the profile picture based on gender
    const profilePic = gender === "male"
      ? `https://avatar.iran.liara.run/public/boy?username=${username}`
      : `https://avatar.iran.liara.run/public/girl?username=${username}`;

    // Create a new user
    const newUser = new User({
      fullName,
      username,
      password: hashedPassword,
      gender,
      profilePic,
    });

    // Save the user to the database
    await newUser.save();

    // Generate and set the JWT token as a cookie
    generateTokenAndSetCookie({ userId: newUser.id, res });

    // Respond with user data (excluding sensitive information like password)
    res.status(201).json({
      _id: newUser.id,
      fullName: newUser.fullName,
      username: newUser.username,
      profilePic: newUser.profilePic,
    });

  } catch (error) {
    console.log("Error in signup controller:", error.message);
    res.status(500).json({ error: "Internal Server Error" });
  }
};


export const login = async (req,res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne( { username });
    const isPasswordCorrect = await bcrypt.compare(password, user?.password || "");

    if(!user || !isPasswordCorrect) {
      return res.status(400).json({ error:"Invalid username or password"});
    }
      generateTokenAndSetCookie(user._id, res);

      res.status(200).json({
        _id:user._id,
        fullName: user.fullName,
        username: user.username,
        profilePic: user.profilePic,
    });
  } catch (error) {
    console.log("Error in login controller", error.message);
    res.status(500).json({error:"Internal Server Error"});
  }
};

export const logout = async (req,res) => {
  try {
    res.cookie("jwt", "" , { maxAge: 0});
    res.status(200).json({ message: "Logged out Successfully"});

  } catch (error) {
    console.log("Error in login controller", error.message);
      res.status(500).json({error:"Internal Server Error"});   
  }
};
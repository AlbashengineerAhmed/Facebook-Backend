const {
  validateEmail,
  validateLength,
  validateUsername,
} = require("../helpers/validation");
const User = require("../models/User");
const Post = require("../models/Post");
const Code = require("../models/Code");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const { generateToken } = require("../helpers/tokens");
const generateCode = require("../helpers/generateCode");
const mongoose = require("mongoose");

// Nodemailer transporter setup
const transporter = nodemailer.createTransport({
  service: "gmail", // Change to "hotmail" for Outlook if preferred
  auth: {
    user: process.env.nodeMailerEmail, // e.g., "ahmedmohamed015014@gmail.com"
    pass: process.env.nodeMailerPassword, // e.g., "fywzhvbglaaooylv"
  },
});

// Send verification email function
const sendVerificationEmail = async (email, first_name, url) => {
  const mailOptions = {
    from: process.env.nodeMailerEmail,
    to: email,
    subject: "Verify Your Email",
    html: `<p>Hello ${first_name},</p>
           <p>Please click the link below to verify your email:</p>
           <a href="${url}">Verify Email</a>
           <p>This link expires in 30 minutes. If you did not request this, please ignore this email.</p>`,
  };
  return await transporter.sendMail(mailOptions);
};

// Send reset code function
const sendResetCode = async (email, first_name, code) => {
  const mailOptions = {
    from: process.env.nodeMailerEmail,
    to: email,
    subject: "Password Reset Code",
    html: `<p>Hello ${first_name},</p>
           <p>Your password reset code is: <strong>${code}</strong></p>
           <p>This code expires soon. If you did not request this, please ignore this email.</p>`,
  };
  return await transporter.sendMail(mailOptions);
};

exports.register = async (req, res) => {
  try {
    const {
      first_name,
      last_name,
      email,
      password,
      username,
      bYear,
      bMonth,
      bDay,
      gender,
    } = req.body;

    if (!validateEmail(email)) {
      return res.status(400).json({ message: "Invalid email address" });
    }
    const check = await User.findOne({ email });
    if (check) {
      return res.status(400).json({
        message:
          "This email address already exists, try with a different email address",
      });
    }

    if (!validateLength(first_name, 3, 30)) {
      return res.status(400).json({
        message: "First name must be between 3 and 30 characters.",
      });
    }
    if (!validateLength(last_name, 3, 30)) {
      return res.status(400).json({
        message: "Last name must be between 3 and 30 characters.",
      });
    }
    if (!validateLength(password, 6, 40)) {
      return res.status(400).json({
        message: "Password must be at least 6 characters.",
      });
    }

    const cryptedPassword = await bcrypt.hash(
      password,
      parseInt(process.env.SALT_ROUND) || 12
    );

    let tempUsername = first_name + last_name;
    let newUsername = await validateUsername(tempUsername);
    const user = await new User({
      first_name,
      last_name,
      email,
      password: cryptedPassword,
      username: newUsername,
      bYear,
      bMonth,
      bDay,
      gender,
      verified: false,
    }).save();

    const emailVerificationToken = generateToken(
      { id: user._id.toString() },
      "30m"
    );
    const url = `${process.env.BASE_URL}/activate/${emailVerificationToken}`;
    await sendVerificationEmail(user.email, user.first_name, url);

    const token = generateToken({ id: user._id.toString() }, "7d");
    res.status(201).json({
      id: user._id,
      username: user.username,
      picture: user.picture,
      first_name: user.first_name,
      last_name: user.last_name,
      token: token,
      verified: user.verified,
      message: "Register Success! Please activate your email to start",
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.activateAccount = async (req, res) => {
  try {
    const token = req.params.token;

    if (!token) {
      return res
        .status(400)
        .json({ message: "Verification token is required" });
    }

    const decoded = jwt.verify(token, process.env.TOKEN_SECRET || "ahmed72261");
    const check = await User.findById(decoded.id);

    if (!check) {
      return res.status(404).json({ message: "User not found" });
    }

    if (check.verified === true) {
      return res
        .status(400)
        .json({ message: "This email is already activated." });
    }

    await User.findByIdAndUpdate(decoded.id, { verified: true });
    res
      .status(200)
      .json({ message: "Account has been activated successfully." });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};



exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({
        message:
          "The email address you entered is not connected to an account.",
      });
    }

    if (!user.verified) {
      return res.status(400).json({
        message: "Please verify your email before logging in.",
      });
    }

    const check = await bcrypt.compare(password, user.password);
    if (!check) {
      return res.status(400).json({
        message: "Invalid credentials. Please try again.",
      });
    }

    const token = generateToken({ id: user._id.toString() }, "7d");
    res.status(200).json({
      id: user._id,
      username: user.username,
      picture: user.picture,
      first_name: user.first_name,
      last_name: user.last_name,
      token: token,
      verified: user.verified,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.sendVerification = async (req, res) => {
  try {
    const id = req.user?.id; // Ensure req.user is set by middleware
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.verified === true) {
      return res.status(400).json({
        message: "This account is already activated.",
      });
    }

    const emailVerificationToken = generateToken(
      { id: user._id.toString() },
      "30m"
    );
    const url = `${process.env.BASE_URL}/activate/${emailVerificationToken}`;
    await sendVerificationEmail(user.email, user.first_name, url);

    res.status(200).json({
      message: "Email verification link has been sent to your email.",
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.findUser = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email }).select("-password");
    if (!user) {
      return res.status(400).json({
        message: "Account does not exist.",
      });
    }
    res.status(200).json({
      email: user.email,
      picture: user.picture,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.sendResetPasswordCode = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email }).select("-password");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    await Code.findOneAndRemove({ user: user._id });
    const code = generateCode(5);
    const savedCode = await new Code({
      code,
      user: user._id,
    }).save();

    await sendResetCode(user.email, user.first_name, code);

    res.status(200).json({
      message: "Email reset code has been sent to your email",
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.validateResetCode = async (req, res) => {
  try {
    const { email, code } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const dbCode = await Code.findOne({ user: user._id });
    if (!dbCode || dbCode.code !== code) {
      return res.status(400).json({ message: "Verification code is wrong." });
    }

    res.status(200).json({ message: "ok" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.changePassword = async (req, res) => {
  try {
    const { email, password } = req.body;
    const cryptedPassword = await bcrypt.hash(
      password,
      parseInt(process.env.SALT_ROUND) || 12
    );
    const updatedUser = await User.findOneAndUpdate(
      { email },
      { password: cryptedPassword },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({ message: "Password updated successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.getProfile = async (req, res) => {
  try {
    const { username } = req.params;
    const user = await User.findById(req.user?.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const profile = await User.findOne({ username }).select("-password");
    if (!profile) {
      return res.status(404).json({ message: "Profile not found" });
    }

    const friendship = {
      friends: false,
      following: false,
      requestSent: false,
      requestReceived: false,
    };

    if (
      user.friends.includes(profile._id) &&
      profile.friends.includes(user._id)
    ) {
      friendship.friends = true;
    }
    if (user.following.includes(profile._id)) {
      friendship.following = true;
    }
    if (user.requests.includes(profile._id)) {
      friendship.requestReceived = true;
    }
    if (profile.requests.includes(user._id)) {
      friendship.requestSent = true;
    }

    const posts = await Post.find({ user: profile._id })
      .populate("user")
      .populate(
        "comments.commentBy",
        "first_name last_name picture username commentAt"
      )
      .sort({ createdAt: -1 });

    await profile.populate("friends", "first_name last_name username picture");
    res.status(200).json({ ...profile.toObject(), posts, friendship });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.updateProfilePicture = async (req, res) => {
  try {
    const { url } = req.body;
    const updatedUser = await User.findByIdAndUpdate(
      req.user?.id,
      { picture: url },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json(url);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.updateCover = async (req, res) => {
  try {
    const { url } = req.body;
    const updatedUser = await User.findByIdAndUpdate(
      req.user?.id,
      { cover: url },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json(url);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.updateDetails = async (req, res) => {
  try {
    const { infos } = req.body;
    const updatedUser = await User.findByIdAndUpdate(
      req.user?.id,
      { details: infos },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json(updatedUser.details);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.addFriend = async (req, res) => {
  try {
    if (req.user?.id === req.params.id) {
      return res
        .status(400)
        .json({ message: "You can't send a request to yourself" });
    }

    const sender = await User.findById(req.user?.id);
    const receiver = await User.findById(req.params.id);

    if (!sender || !receiver) {
      return res.status(404).json({ message: "User not found" });
    }

    if (
      receiver.requests.includes(sender._id) ||
      receiver.friends.includes(sender._id)
    ) {
      return res.status(400).json({ message: "Already sent or friends" });
    }

    await receiver.updateOne({
      $push: { requests: sender._id, followers: sender._id },
    });
    await sender.updateOne({ $push: { following: receiver._id } });

    res.status(200).json({ message: "Friend request has been sent" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.cancelRequest = async (req, res) => {
  try {
    if (req.user?.id === req.params.id) {
      return res
        .status(400)
        .json({ message: "You can't cancel a request to yourself" });
    }

    const sender = await User.findById(req.user?.id);
    const receiver = await User.findById(req.params.id);

    if (!sender || !receiver) {
      return res.status(404).json({ message: "User not found" });
    }

    if (
      !receiver.requests.includes(sender._id) ||
      receiver.friends.includes(sender._id)
    ) {
      return res
        .status(400)
        .json({ message: "Request not found or already friends" });
    }

    await receiver.updateOne({
      $pull: { requests: sender._id, followers: sender._id },
    });
    await sender.updateOne({ $pull: { following: receiver._id } });

    res.status(200).json({ message: "You successfully canceled the request" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.follow = async (req, res) => {
  try {
    if (req.user?.id === req.params.id) {
      return res.status(400).json({ message: "You can't follow yourself" });
    }

    const sender = await User.findById(req.user?.id);
    const receiver = await User.findById(req.params.id);

    if (!sender || !receiver) {
      return res.status(404).json({ message: "User not found" });
    }

    if (
      receiver.followers.includes(sender._id) ||
      sender.following.includes(receiver._id)
    ) {
      return res.status(400).json({ message: "Already following" });
    }

    await receiver.updateOne({ $push: { followers: sender._id } });
    await sender.updateOne({ $push: { following: receiver._id } });

    res.status(200).json({ message: "Follow success" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.unfollow = async (req, res) => {
  try {
    if (req.user?.id === req.params.id) {
      return res.status(400).json({ message: "You can't unfollow yourself" });
    }

    const sender = await User.findById(req.user?.id);
    const receiver = await User.findById(req.params.id);

    if (!sender || !receiver) {
      return res.status(404).json({ message: "User not found" });
    }

    if (
      !receiver.followers.includes(sender._id) ||
      !sender.following.includes(receiver._id)
    ) {
      return res.status(400).json({ message: "Not following" });
    }

    await receiver.updateOne({ $pull: { followers: sender._id } });
    await sender.updateOne({ $pull: { following: receiver._id } });

    res.status(200).json({ message: "Unfollow success" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.acceptRequest = async (req, res) => {
  try {
    if (req.user?.id === req.params.id) {
      return res
        .status(400)
        .json({ message: "You can't accept a request from yourself" });
    }

    const receiver = await User.findById(req.user?.id);
    const sender = await User.findById(req.params.id);

    if (!sender || !receiver) {
      return res.status(404).json({ message: "User not found" });
    }

    if (!receiver.requests.includes(sender._id)) {
      return res
        .status(400)
        .json({ message: "No request found or already friends" });
    }

    await receiver.updateOne({
      $push: { friends: sender._id, following: sender._id },
      $pull: { requests: sender._id },
    });
    await sender.updateOne({
      $push: { friends: receiver._id, followers: receiver._id },
    });

    res.status(200).json({ message: "Friend request accepted" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.unfriend = async (req, res) => {
  try {
    if (req.user?.id === req.params.id) {
      return res.status(400).json({ message: "You can't unfriend yourself" });
    }

    const sender = await User.findById(req.user?.id);
    const receiver = await User.findById(req.params.id);

    if (!sender || !receiver) {
      return res.status(404).json({ message: "User not found" });
    }

    if (
      !receiver.friends.includes(sender._id) ||
      !sender.friends.includes(receiver._id)
    ) {
      return res.status(400).json({ message: "Not friends" });
    }

    await receiver.updateOne({
      $pull: {
        friends: sender._id,
        following: sender._id,
        followers: sender._id,
      },
    });
    await sender.updateOne({
      $pull: {
        friends: receiver._id,
        following: receiver._id,
        followers: receiver._id,
      },
    });

    res.status(200).json({ message: "Unfriend request accepted" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.deleteRequest = async (req, res) => {
  try {
    if (req.user?.id === req.params.id) {
      return res
        .status(400)
        .json({ message: "You can't delete a request from yourself" });
    }

    const receiver = await User.findById(req.user?.id);
    const sender = await User.findById(req.params.id);

    if (!sender || !receiver) {
      return res.status(404).json({ message: "User not found" });
    }

    if (!receiver.requests.includes(sender._id)) {
      return res.status(400).json({ message: "No request found" });
    }

    await receiver.updateOne({
      $pull: { requests: sender._id, followers: sender._id },
    });
    await sender.updateOne({ $pull: { following: receiver._id } });

    res.status(200).json({ message: "Delete request accepted" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.search = async (req, res) => {
  try {
    const { searchTerm } = req.params;
    const results = await User.find({ $text: { $search: searchTerm } }).select(
      "first_name last_name username picture"
    );
    res.status(200).json(results);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.addToSearchHistory = async (req, res) => {
  try {
    const { searchUser } = req.body;
    const user = await User.findById(req.user?.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const search = { user: searchUser, createdAt: new Date() };
    const check = user.search.find((x) => x.user.toString() === searchUser);

    if (check) {
      await User.updateOne(
        { _id: req.user.id, "search._id": check._id },
        { $set: { "search.$.createdAt": new Date() } }
      );
    } else {
      await User.findByIdAndUpdate(req.user.id, { $push: { search } });
    }

    res.status(200).json({ message: "Search history updated" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.getSearchHistory = async (req, res) => {
  try {
    const results = await User.findById(req.user?.id)
      .select("search")
      .populate("search.user", "first_name last_name username picture");

    if (!results) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json(results.search);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.removeFromSearch = async (req, res) => {
  try {
    const { searchUser } = req.body;
    const updatedUser = await User.updateOne(
      { _id: req.user?.id },
      { $pull: { search: { user: searchUser } } }
    );

    if (!updatedUser.modifiedCount) {
      return res.status(404).json({ message: "Search entry not found" });
    }

    res.status(200).json({ message: "Search entry removed" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.getFriendsPageInfos = async (req, res) => {
  try {
    const user = await User.findById(req.user?.id)
      .select("friends requests")
      .populate("friends", "first_name last_name picture username")
      .populate("requests", "first_name last_name picture username");

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const sentRequests = await User.find({
      requests: mongoose.Types.ObjectId(req.user.id),
    }).select("first_name last_name picture username");

    res.status(200).json({
      friends: user.friends,
      requests: user.requests,
      sentRequests,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

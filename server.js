const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const swaggerJSDoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const dotenv = require("dotenv");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth").OAuth2Strategy;

const app = express();
dotenv.config();
const PORT = process.env.PORT;

app.use(bodyParser.json());
app.set("view engine", "ejs");
app.use(
  session({
    resave: false,
    saveUninitialized: true,
    secret: "SECRET",
  })
);

// Swagger setup
const swaggerOptions = {
    swaggerDefinition: {
      openapi: "3.0.0",
      info: {
        title: "Express Swagger API",
        version: "1.0.0",
        description: "APIs documentation for the Express.js app",
      },
      servers: [{ url: "http://localhost:3000" }],
      components: {
        securitySchemes: {
          bearerAuth: {
            type: "http",
            scheme: "bearer",
            bearerFormat: "JWT",
            in: "header",
          },
        },
        schemas: {
          User: {
            type: "object",
            properties: {
              photo: { type: "string" },
              name: { type: "string" },
              bio: { type: "string" },
              phone: { type: "string" },
              email: { type: "string" },
              password: { type: "string" },
              isPrivate: { type: "boolean" },
              isAdmin: { type: "boolean" },
            },
          },
        },
      },
      security: [{ bearerAuth: [] }],
    },
    apis: ["./server.js"], // Path to the API files
  };

/**
 * @swagger
 * tags:
 *   - name: Authentication
 *     description: APIs for user authentication
 *   - name: Users
 *     description: APIs for user management
 */

const swaggerSpec = swaggerJSDoc(swaggerOptions);
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

mongoose.connect(process.env.MONGO_URL);
const db = mongoose.connection;
db.on("error", console.error.bind(console, "MongoDB connection error:"));
db.once("open", function () {
  console.log("Connected to MongoDB");
});

let userProfile;

app.use(passport.initialize());
app.use(passport.session());

app.set("view engine", "ejs");

app.get("/success", (req, res) => res.send(userProfile));
app.get("/error", (req, res) => res.send("error logging in"));

passport.serializeUser(function (user, cb) {
  cb(null, user);
});

passport.deserializeUser(function (obj, cb) {
  cb(null, obj);
});

const GOOGLE_CLIENT_ID =
  process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
passport.use(
  new GoogleStrategy(
    {
      clientID: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/callback",
    },
    function (accessToken, refreshToken, profile, done) {
      userProfile = profile;
      return done(null, userProfile);
    }
  )
);

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/error" }),
  function (req, res) {
    // Successful authentication, redirect success.
    res.redirect("/success");
  }
);

// User Schema
const userSchema = new mongoose.Schema({
  photo: String,
  name: String,
  bio: String,
  phone: String,
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isPrivate: { type: Boolean, default: false },
  isAdmin: { type: Boolean, default: false },
});

const User = mongoose.model("User", userSchema);

// Middleware for token decoding
async function verifyToken(req, res, next) {
  const token = req.headers["authorization"];
  if (!token)
    return res
      .status(401)
      .json({ message: "Access denied. No token provided." });

  try {
    const decoded = jwt.verify(token.split(' ')[1], process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(400).json({ message: "Invalid token." });
  }
}

app.get("/", function (req, res) {
  res.render("pages/auth");
});

// Register API

/**
 * @swagger
 * /register:
 *   post:
 *     summary: Register a new user
 *     tags: [Users]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/User'
 *     responses:
 *       201:
 *         description: User registered successfully
 *       400:
 *         description: Bad request or email already exists
 */
app.post("/register", async (req, res) => {
  try {
    const { photo, name, bio, phone, email, password, isPrivate, isAdmin } =
      req.body;
    if (!bio || !name || !email || !password || !phone)
      return res.status(400).json({ message: "All fields are required." });

    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ message: "Email is already registered." });
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      photo,
      name,
      bio,
      phone,
      email,
      password: hashedPassword,
      isPrivate,
      isAdmin,
    });
    await user.save();
    res.status(201).json({ message: "User registered successfully." });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

/**
 * @swagger
 * /admin/register:
 *   post:
 *     summary: Register a new admin user
 *     tags: [Admin]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               photo:
 *                 type: string
 *               name:
 *                 type: string
 *               bio:
 *                 type: string
 *               phone:
 *                 type: string
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *               isPrivate:
 *                 type: boolean
 *               isAdmin:
 *                 type: boolean
 *             required:
 *               - name
 *               - email
 *               - password
 *               - phone
 *     responses:
 *       201:
 *         description: User registered successfully
 *       400:
 *         description: Bad request or email already exists
 */

app.post("/admin/register", async (req, res) => {
    try {
      const { photo, name, bio, phone, email, password, isPrivate, isAdmin } =
        req.body;
      if (!bio || !name || !email || !password || !phone)
        return res.status(400).json({ message: "All fields are required." });
  
      const existingUser = await User.findOne({ email, isAdmin: true });
      if (existingUser)
        return res.status(400).json({ message: "Email is already registered." });
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = new User({
        photo,
        name,
        bio,
        phone,
        email,
        password: hashedPassword,
        isPrivate,
        isAdmin: true,
      });
      await user.save();
      res.status(201).json({ message: "User registered successfully." });
    } catch (err) {
      res.status(400).json({ message: err.message });
    }
  });



// Login API
/**
 * @swagger
 * /login:
 *   post:
 *     summary: Login with email and password
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: JWT token generated successfully
 *       400:
 *         description: Invalid email or password
 */
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res
        .status(400)
        .json({ message: "Email and password are required." });
    const user = await User.findOne({ email });
    if (!user)
      return res.status(400).json({ message: "Invalid email or password." });
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword)
      return res.status(400).json({ message: "Invalid email or password." });

    const token = jwt.sign(
      { email: user.email, isAdmin: user.isAdmin, isPrivate: user.isPrivate },
      process.env.JWT_SECRET
    );
    res.json({ token });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Get Profile Details API
/**
 * @swagger
 * /profile:
 *   get:
 *     summary: Get profile details of logged-in user
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile details
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 *       401:
 *         description: Unauthorized
 *       400:
 *         description: Invalid token
 *       404:
 *         description: User not found
 */
app.get("/profile", verifyToken, async (req, res) => {
  try {
    const loggedInUser = req.user;
    const userEmail = loggedInUser.email;
    const user = await db
      .collection("users")
      .findOne({ email: userEmail }, { projection: { _id: 0 } });
    if (!user) return res.status(404).json({ message: "User not found." });
    res.json(user);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Edit User Details API
/**
 * @swagger
 * /profile/edit:
 *   put:
 *     summary: Update user details
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               photo:
 *                 type: string
 *               name:
 *                 type: string
 *               bio:
 *                 type: string
 *               phone:
 *                 type: string
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *             example:
 *               photo: http://example.com/profile.jpg
 *               name: John Doe
 *               bio: Software Engineer
 *               phone: 1234567890
 *               email: john@example.com
 *               password: newpassword
 *     responses:
 *       200:
 *         description: User details updated successfully
 *       400:
 *         description: Bad request or email already exists
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: User not found
 */
app.put("/profile/edit", verifyToken, async (req, res) => {
  try {
    const loggedInUser = req.user;
    const userEmail = loggedInUser.email;
    const { photo, name, bio, phone, email, password } = req.body;

    // Check if the new email is already taken
    if (email && email !== userEmail) {
      const existingUser = await db.collection("users").findOne({ email });
      if (existingUser) {
        return res.status(400).json({ message: "Email already exists." });
      }
    }

    // Update user details
    const updateData = {};
    if (photo) updateData.photo = photo;
    if (name) updateData.name = name;
    if (bio) updateData.bio = bio;
    if (phone) updateData.phone = phone;
    if (email) updateData.email = email;
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      updateData.password = hashedPassword;
    }
    await db
      .collection("users")
      .updateOne({ email: userEmail }, { $set: updateData });

    res.json({ message: "User details updated successfully." });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Upload Photo or Provide Image URL API
/**
 * @swagger
 * /profile/photo:
 *   put:
 *     summary: Update user photo
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               photo:
 *                 type: string
 *             example:
 *               photo: http://example.com/profile.jpg
 *     responses:
 *       200:
 *         description: User photo updated successfully
 *       400:
 *         description: Bad request or missing photo URL
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: User not found
 */
app.put("/profile/photo", verifyToken, async (req, res) => {
  try {
    const loggedInUser = req.user;
    const userEmail = loggedInUser.email;
    const { photo } = req.body;

    if (!photo) {
      return res
        .status(400)
        .json({ message: "Please provide photo or image URL." });
    }

    const updateData = {};
    if (photo) updateData.photo = photo;

    await db
      .collection("users")
      .updateOne({ email: userEmail }, { $set: updateData });

    res.json({ message: "User photo updated successfully." });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Choose Profile Privacy API
/**
 * @swagger
 * /profile/privacy:
 *   put:
 *     summary: Update user privacy setting
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               isPrivate:
 *                 type: boolean
 *             example:
 *               isPrivate: true
 *     responses:
 *       200:
 *         description: User privacy setting updated successfully
 *       400:
 *         description: Bad request
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: User not found
 */
app.put("/profile/privacy", verifyToken, async (req, res) => {
  try {
    const loggedInUser = req.user;
    const userEmail = loggedInUser.email;
    const { isPrivate } = req.body;

    // Update user's privacy setting
    await db
      .collection("users")
      .updateOne({ email: userEmail }, { $set: { isPrivate } });

    res.json({ message: "User privacy setting updated successfully." });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// List Users API
/**
 * @swagger
 * /users:
 *   get:
 *     summary: Get list of users
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *         description: Page number
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *         description: Number of users per page
 *     responses:
 *       200:
 *         description: List of users
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/User'
 *       400:
 *         description: Bad request
 *       401:
 *         description: Unauthorized
 */
app.get("/users", verifyToken, async (req, res) => {
  try {
    const loggedInUser = req.user;
    const { page = 1, limit = 10 } = req.query;
    const skip = (page - 1) * limit;

    // If the user is admin, return all users
    if (loggedInUser.isAdmin) {
      const users = await db
        .collection("users")
        .find({}, { projection: { _id: 0, password: 0 } })
        .skip(parseInt(skip))
        .limit(parseInt(limit))
        .toArray();
      res.json(users);
    } else {
      // If the user is not admin, return only public users
      const users = await db
        .collection("users")
        .find({ isPrivate: false }, { projection: { _id: 0, password: 0 } })
        .skip(parseInt(skip))
        .limit(parseInt(limit))
        .toArray();
      res.json(users);
    }
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

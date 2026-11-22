const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const http = require("http");
const { Server } = require("socket.io");
const { EventEmitter } = require("events");
require("dotenv").config();

const User = require("./models/User");
const verifyToken = require("./middleware/auth");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json());

mongoose.connect(process.env.MONGO_URI)
.then(() => console.log("Database connected"))
.catch(err => console.log(err));

// Signup
app.post("/signup", async (req, res) => {
    try {
        const { username, email, password } = req.body;

        const existing = await User.findOne({ email });
        if (existing) {
            return res.status(409).json({ message: "Email already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = await User.create({
            username,
            email,
            password: hashedPassword
        });

        res.status(201).json({ message: "Signup successful" });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// Login
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
        { id: user._id, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
    );

    res.json({ message: "Login successful", token });
});

// Protected route
app.get("/profile", verifyToken, (req, res) => {
    res.json({
        message: "Protected route accessed",
        user: req.user
    });
});
const Note = require("./models/Note");

// Create Note
app.post("/notes", verifyToken, async (req, res) => {
    const note = await Note.create({
        ...req.body,
        userId: req.user.id
    });

    res.status(201).json(note);
});

// Read My Notes
app.get("/notes", verifyToken, async (req, res) => {
    const notes = await Note.find({ userId: req.user.id });
    res.json(notes);
});

// Update My Note
app.put("/notes/:id", verifyToken, async (req, res) => {
    const note = await Note.findOneAndUpdate(
        { _id: req.params.id, userId: req.user.id },
        req.body,
        { new: true }
    );

    if (!note) return res.status(404).json({ message: "Note not found" });

    res.json(note);
});

// Delete My Note
app.delete("/notes/:id", verifyToken, async (req, res) => {
    const note = await Note.findOneAndDelete({
        _id: req.params.id,
        userId: req.user.id
    });

    if (!note) return res.status(404).json({ message: "Note not found" });

    res.json({ message: "Note deleted" });
});
function adminOnly(req, res, next) {
    if (req.user.role !== "admin") {
        return res.status(403).json({
            message: "Admin access required"
        });
    }

    next();
}

app.get("/admin", verifyToken, adminOnly, (req, res) => {
    res.json({ message: "Welcome Admin" });
});
io.on("connection", (socket) => {
    console.log("User connected:", socket.id);

    socket.on("chatMessage", (message) => {
        io.emit("chatMessage", message);
    });

    socket.on("disconnect", () => {
        console.log("User disconnected");
    });
});
const events = new EventEmitter();

events.on("userRegistered", (username) => {
    console.log("New user registered:", username);
});
events.emit("userRegistered", username);
server.listen(3000, () => {
    console.log("Server running on port 3000");
});
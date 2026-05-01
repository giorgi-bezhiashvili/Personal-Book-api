const express = require("express");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcrypt");
const https = require("https");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const Joi = require("joi");
const helmet = require("helmet");
const { v4: uuidv4 } = require("uuid");
const { body, validationResult } = require("express-validator");

dotenv.config();
const app = express();
app.use(express.json());
app.use(helmet({ xPoweredBy: false }));

// --- CONSTANTS & FILE HELPERS ---
const DATA_PATH = path.join(__dirname, "data.json");
const FAKE_HASH = "$2b$10$C6Q8XjO4vXzG9.Y7.Q1eOu.uK9O3e4R5t6y7u8i9o0p1a2s3d4f5g";

const getFileData = () => {
  try {
    return JSON.parse(fs.readFileSync(DATA_PATH, "utf8"));
  } catch { return []; }
};

const saveFileData = (data) => fs.writeFileSync(DATA_PATH, JSON.stringify(data, null, 2));

// --- MIDDLEWARE ---

// DRY Error Handler for express-validator
const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  next();
};

function authenticationToken(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCES_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// DRY User Lookup & Authorization
const findUserAndAuthorize = (req, res, next) => {
  if (req.user.id !== req.params.id) return res.status(403).send("Access denied");
  
  const users = getFileData();
  const userIndex = users.findIndex((u) => u.id === req.params.id);
  
  if (userIndex === -1) return res.status(404).send("User not found");
  
  req.users = users;
  req.userIndex = userIndex;
  req.currentUser = users[userIndex];
  next();
};

const loginSchema = Joi.object({
  email: Joi.string().email(),
  userName: Joi.string().alphanum(),
  password: Joi.string().min(8).max(20).required(),
}).xor("userName", "email");


app.post("/register", [
  body("mail").isEmail().withMessage("Valid email required"),
  body("userName").notEmpty(),
  body("password").isLength({ min: 8 }),
  validate 
], async (req, res) => {
  try {
    const { userName, mail, password } = req.body;
    const users = getFileData();

    if (users.some(u => u.userName === userName || u.email === mail)) {
      return res.status(409).send("User already exists");
    }

    const newUser = {
      id: uuidv4(),
      userName,
      email: mail,
      password: await bcrypt.hash(password, 10),
      books: []
    };

    users.push(newUser);
    saveFileData(users);
    res.status(201).send("User Created successfully");
  } catch (err) {
    res.status(500).send("Server Error");
  }
});

app.post("/login", async (req, res) => {
  const { error } = loginSchema.validate(req.body);
  if (error) return res.status(400).send(error.details[0].message);

  const { userName, email, password } = req.body;
  const users = getFileData();
  const user = users.find(u => userName ? u.userName === userName : u.email === email);

  const isMatch = await bcrypt.compare(password, user?.password || FAKE_HASH);
  if (!user || !isMatch) return res.status(401).send("Invalid credentials");

  const accessToken = jwt.sign({ id: user.id, userN: user.userName }, process.env.ACCES_TOKEN_SECRET, { expiresIn: "1h" });
  res.json({ accessToken });
});

// --- BOOK ROUTES ---

app.use("/:id/book", authenticationToken, findUserAndAuthorize);

app.get("/:id/book", (req, res) => {
  res.json(req.currentUser.books || []);
});

app.post("/:id/book", (req, res) => {
  const newBook = { ...req.body, bookId: uuidv4() };
  req.currentUser.books = req.currentUser.books || [];
  req.currentUser.books.push(newBook);
  
  saveFileData(req.users);
  res.status(201).json(newBook);
});

app.put("/:id/book/:bookId", (req, res) => {
  const { bookId } = req.params;
  const index = req.currentUser.books.findIndex(b => b.bookId === bookId);
  
  if (index === -1) return res.status(404).send("Book not found");
  
  req.currentUser.books[index] = { ...req.currentUser.books[index], ...req.body };
  saveFileData(req.users);
  res.json(req.currentUser.books[index]);
});

app.delete("/:id/book/:bookId", (req, res) => {
  req.currentUser.books = req.currentUser.books.filter(b => b.bookId !== req.params.bookId);
  saveFileData(req.users);
  res.json(req.currentUser.books);
});

const httpsOptions = {
  key: fs.readFileSync(path.join(__dirname, "localhost.key")),
  cert: fs.readFileSync(path.join(__dirname, "localhost.crt"))
};

https.createServer(httpsOptions, app).listen(8080, () => {
  console.log("server spinning on port 8080");
});
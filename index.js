const express = require(`express`);
const app = express();
const fs = require(`fs`);
const path = require(`path`);
const bcrypt = require(`bcrypt`);
const key = fs.readFileSync(path.join(__dirname, `localhost.key`));
const cert = fs.readFileSync(path.join(__dirname, `localhost.crt`));
const https = require(`https`);
const httpsNeccecities = { key: key, cert: cert };
const { query, validationResult, body } = require("express-validator");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const Joi = require(`joi`);
const helmet = require(`helmet`);
dotenv.config();
app.disable("x-powered-by");
const dummyHash = `$2b$10$eFN4uM/jBviTKQFDeAxTc.XtwRl3ujt4yKYRi0oDpd5nlDxmEcgZS`


app.use(
  helmet({
    xPoweredBy: false,
  }),
);

function authenticationToken(req, res, next) {
  const authHeader = req.headers[`authorization`];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) {
    return res.status(401);
  }
  jwt.verify(token, process.env.ACCES_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

const loginSceme = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(8).max(20).required(),
  userName: Joi.string().alphanum(),
}).xor(`userName`, "email");

app.use(express.json());
const getFileData = () => {
  try {
    return JSON.parse(
      fs.readFileSync(path.join(__dirname, `data.json`), "utf8"),
    );
  } catch {
    return [];
  }
};
const saveFileData = (data) => {
  fs.writeFileSync(
    path.join(__dirname, `data.json`),
    JSON.stringify(data, null, 2),
  );
};

app.post(
  "/register",
  [
    body("mail").isEmail().withMessage(`Please enter valid email`),
    body(`userName`).notEmpty().withMessage(`Username is required`),
    body(`password`).isLength({ min: 8 }).withMessage(`Password too short`),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { userName, mail, password } = req.body;

    const users = getFileData();
    try {
      if (users.find((u) => u.userName === userName)) {
        return res.status(404).send(`User already exists`);
      }
      if (users.find((u) => u.mail === mail)) {
        return res.status(404).send(`User already exists`);
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = {
        userName: userName,
        password: hashedPassword,
        email: mail,
      };
      users.push(newUser);
      res.send(`User Created succesfully`);
      saveFileData(users);
    } catch (err) {
      console.log(err);
      return res.status(404).send(`Server Error`);
    }
  },
);
const FAKE_HASH = "$2b$10$C6Q8XjO4vXzG9.Y7.Q1eOu.uK9O3e4R5t6y7u8i9o0p1a2s3d4f5g";

app.post(`/login`, async (req, res) => {
  const { error } = loginSceme.validate(req.body);
  if (error) return res.status(400).send("Invalid request");

  try {
    const { userName, email, password } = req.body;
    const users = getFileData();

    // 1. Look for the user
    const user = users.find((u) =>
      userName ? u.userName === userName : u.email === email
    );

    // 2. THE SHIELD: Always select a valid-looking hash.
    // If the user isn't found, we use the FAKE_HASH so bcrypt still runs slowly.
    const hashToVerify = user ? user.password : FAKE_HASH;

    // 3. THE HEAVY LIFT: This takes ~100ms for EVERY request.
    const isMatch = await bcrypt.compare(password, hashToVerify);

    // 4. THE GATEKEEPER: Check both conditions only AFTER the math is done.
    if (!user || !isMatch) {
      return res.status(401).send("Username or password isn't correct");
    }

    const accessToken = jwt.sign(
      { id: user.id, userN: user.userName }, 
      process.env.ACCES_TOKEN_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ message: "Login successful", accessToken });
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

const server = https.createServer(httpsNeccecities, app);
server.listen(8080, (req, res) => {
  console.log(`Server is spinning on port 8080`);
});

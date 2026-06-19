const express = require("express");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const cors = require("cors");

dotenv.config();
const saltRounds = process.env.SALT_ROUNDS;
const secret_key = process.env.SECRET_KEY;
const port = process.env.PORT;

const dataFile = path.join(__dirname, "db.json");

const app = express();
app.use(express.json());
app.use(cors());

function auth(req, res, next) {
  console.log(req.headers);
  if (!req.headers.authorization) {
    res.send({ mes: "un authorized", status: 401 });
  }
  const [scheme, token] = req.headers.authorization.split(" ");
  if (scheme !== "Bearer" || !token) {
    res.send({ mes: "un authorized", status: 401 });
  }
  const decoded = jwt.verify(token, secret_key);
  console.log(decoded);
  req.user = decoded;
  console.log("req", req.user);
  next();
}

app.get("/", auth, (req, res) => {
  fs.readFile(dataFile, "utf-8", (err, data) => {
    if (err) throw err;
    res.send(data);
  });
});

app.get("/search", (req, res) => {
  const { name } = req.query;
  const array = JSON.parse(fs.readFileSync(dataFile, "utf-8"));
  const searchedValue = array.filter((user) =>
    user.username.toLowerCase().includes(name.toLowerCase()),
  );
  if (searchedValue.length > 0) {
    res.send(searchedValue);
  } else {
    res.send("no data found");
  }
});

app.get("/:id", auth, (req, res) => {
  const id = parseInt(req.params.id);
  const array = JSON.parse(fs.readFileSync(dataFile, "utf-8"));
  const matchedIndex = array.find((x) => x.id == id);
  if (matchedIndex) {
    res.send(matchedIndex);
  } else {
    res.send("user not available");
  }
});

app.post("/", (req, res) => {
  const { username, password } = req.body;
  const array = JSON.parse(fs.readFileSync(dataFile, "utf-8"));
  const id = array.length + 1;

  const findUserName = array.find((x) => x.username == username);
  if (findUserName) {
    res.send({ mes: "already username taken" });
  }
  const hashedPassword = bcrypt.hashSync(password, parseInt(saltRounds));
  const token = jwt.sign({ ...req.body, password: hashedPassword }, secret_key);
  const newUser = { id, username, password: hashedPassword, token };
  array.push(newUser);
  fs.writeFileSync(dataFile, JSON.stringify(array));
  res.send({ mes: "data added succesfully", status: 200, data: newUser });
});

app.post("/login", auth, (req, res) => {
  const { username, password } = req.body;
  const array = JSON.parse(fs.readFileSync(dataFile, "utf-8"));
  const findObj = array.find((x) => x.username == username);
  if (findObj) {
    const passwordcheck = bcrypt.compareSync(password, findObj.password);
    if (passwordcheck) {
      res.send({ mes: "login success", status: 200, data: findObj });
    } else {
      res.send("invalid cred");
    }
  } else {
    res.send("user not found");
  }
});

app.put("/:id", (req, res) => {
  const body = req.body;
  const id = parseInt(req.params.id);
  const array = JSON.parse(fs.readFileSync(dataFile, "utf-8"));
  const matchedIndex = array.findIndex((x) => x.id == id);
  array[matchedIndex] = { id, ...body };
  fs.writeFileSync(dataFile, JSON.stringify(array));
  res.send("updated");
});

app.patch("/:id", (req, res) => {
  const body = req.body;
  const id = parseInt(req.params.id);
  const array = JSON.parse(fs.readFileSync(dataFile, "utf-8"));
  const matchedIndex = array.findIndex((x) => x.id == id);
  array[matchedIndex] = { ...array[matchedIndex], ...body };
  fs.writeFileSync(dataFile, JSON.stringify(array));
  res.send("updated");
});

app.delete("/:id", (req, res) => {
  const id = parseInt(req.params.id);
  const array = JSON.parse(fs.readFileSync(dataFile, "utf-8"));
  const filteredData = array.filter((x) => x.id != id);
  fs.writeFileSync(dataFile, JSON.stringify(filteredData));
  res.send("deleted");
});

app.listen(port, () => {
  console.log("server is running...");
});

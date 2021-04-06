const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const sessions = require("client-sessions");

const port = 3000;
const app = express();

/* db-stuff */
const mongoURI = process.env.MONGO_DB_URI;
mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });
const db = mongoose.connection;
let User = mongoose.model(
  "User",
  new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String },
  })
);

db.on("error", console.error.bind(console, "connection error:"));

db.once("open", function () {
  console.log("we are connected");
});

/* Middleware*/
app.use(express.static("public"));

function loginRequired(req, res, next) {
  if (!req.user) {
    return res.redirect("/login");
  }
  next();
}

/* App setup */

app.set("view engine", "pug");
app.use(bodyParser.urlencoded({ extended: false }));
app.use(
  sessions({
    cookieName: "session",
    secret: "blargadeeblargblarg",
    duration: 24 * 60 * 60 * 1000,
  })
);

app.use(function (req, res, next) {
  if (!(req.session && req.session.userId)) {
    return next();
  }
  User.findById(req.session.userId, (err, user) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      return next();
    }
    user.password = undefined;
    req.user = user;
    res.locals.user = user;
    next();
  });
});

/* routes */

app.get("/", function (req, res) {
  res.render("index");
});

app.get("/login", function (req, res) {
  res.render("login");
});

app.post("/login", function (req, res) {
  User.findOne({ email: req.body.email }, (err, user) => {
    if (!user || err || !bcrypt.compareSync(user.password, req.body.password)) {
      res.render("login", { error: "Incorrect email / password" });
    }
    req.session.userId = user._id;
    res.redirect("/dashboard");
  });
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/logout", function (req, res) {
  req.session.userId = undefined;
  res.redirect("/login");
});

app.post("/register", function (req, res) {
  req.body.password = bcrypt.hashSync(req.body.password, 14);
  const user = new User(req.body);
  user.save((err) => {
    if (err) {
      res.render("register", { error: "Could not create user" });
    } else {
      req.session.userId = user._id;
      res.redirect("/dashboard");
    }
  });
});

app.get("/dashboard", loginRequired, function (req, res, next) {
  res.render("dashboard");
});

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});

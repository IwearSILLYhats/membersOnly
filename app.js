const path = require("node:path");
const { Pool } = require("pg");
const express = require("express");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcryptjs");
const { body, validationResult } = require("express-validator");
require("dotenv").config();

const pool = new Pool({
  connectionString: process.env.connectionSTRING,
});

const app = express();
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(
  session({
    store: new pgSession({
      createTableIfMissing: true,
      pool: pool,
    }),
    secret: process.env.secret,
    resave: false,
    saveUninitialized: false,
  }),
);

app.use(passport.session());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "/public")));

app.use((req, res, next) => {
  res.locals.currentUser = req.user;
  next();
});

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const { rows } = await pool.query(
        "SELECT * FROM users WHERE username = $1",
        [username],
      );
      const user = rows[0];
      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return done(null, false, { message: "Incorrect password" });
      }

      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }),
);
passport.serializeUser((user, done) => {
  done(null, user.userid);
});
passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE userid = $1", [
      id,
    ]);
    const user = rows[0];

    done(null, user);
  } catch (err) {
    console.log(err);
    done(err);
  }
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send(err);
});

app.get("/sign-up", (req, res) => res.render("sign-up"));
app.post("/sign-up", async (req, res, next) => {
  try {
    const newUser = {
      username: req.body.username,
      fName: req.body.fName,
      lName: req.body.lName,
    };
    const existingUser = await pool.query({
      text: `
        SELECT
          *
        FROM
          users
        WHERE
          username = $1`,
      values: [newUser.username],
    });
    if (existingUser.rows[0]) {
      return res.render("sign-up", {
        error: "Username already  exists",
        newUser: newUser,
      });
    }
    if (req.body.password !== req.body.confirm) {
      return res.render("sign-up", {
        error: "Passwords do not match",
        newUser: newUser,
      });
    }
    bcrypt.hash(req.body.password, 10, async (err, hashedPassword) => {
      if (err) throw err;
      await pool.query(
        "INSERT INTO users (username, password, fname, lname, membership, admin) VALUES ($1, $2, $3, $4, false, false)",
        [newUser.username, hashedPassword, newUser.fName, newUser.lName],
      );
    });
    res.redirect("/");
  } catch (err) {
    console.log(err);
    res.redirect("/");
    return next(err);
  }
});

app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
    failureMessage: "Incorrect username or password",
  }),
);

app.get("/log-out", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.post("/upgrade", async (req, res) => {
  if (req.body.secret === process.env.validation) {
    await pool.query({
      text: `
          UPDATE
            users
          SET
            membership = true
          WHERE
            userid = $1`,
      values: [req.body.id],
    });
    res.redirect("/");
  } else {
    res.render("index", { error: ["Sucks to suck"] });
  }
});

app.get("/topics/create", (req, res) => {
  console.log(req?.user);
  res.render("topicForm");
});

app.post("/topics/create", async (req, res) => {
  await pool.query({
    text: `
    INSERT INTO
      topics 
        (title, timestamp, content, author)
      VALUES
        ($1, NOW(), $2, $3)`,
    values: [req.body.title, req.body.content, req.body.userid]
  });
  res.redirect("/");
});

app.get("/", async (req, res) => {
  const { rows } = await pool.query({
    text: `
    SELECT
      *
    FROM
      topics
    LEFT JOIN
      users
    ON
      userid = author`,
    values: []
  })
  res.render("index", { topics: rows, error: req.session.messages });
});

app.get("/chat/:id", async ( req, res ) => {
  const [topic, posts] = await Promise.all([
    pool.query({
      text: `
        SELECT
          *
        FROM
          topics
        WHERE
          topicid = $1`,
      values: [req.params.id]
    }),
    pool.query({
    text: `
      SELECT
        *
      FROM
        posts
      WHERE
        topic = $1
        `,
    values: [req.params.id]
  })]);

  if(topic !== null) {
    res.render('chat', {
      topic: topic.rows[0],
      posts: posts.rows
    })
  } else {
    res.redirect("/")
  }
})

app.listen(3000, () =>
  console.log(`app listening on port ${process.env.PORT}`),
);

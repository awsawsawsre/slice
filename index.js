import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import env from "dotenv";


const app = express();
const port = 3000;
env.config();

const db = new pg.Client({
  user: process.env.PGuser,
  host: process.env.PGhost,
  database: process.env.PGdatabase,
  password: process.env.PGpassword,
  port: process.env.PGPORT,
});
db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
  secret: process.env.MAIN,
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 1000 * 60 * 30
  }
  
}));

app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
  res.render("login.ejs");
});

app.get("/enroll", (req, res) => {
  res.render("enroll.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/password", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("password.ejs")
  }
});

app.get("/auth", async (req,res) => {
  if (req.isAuthenticated()) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [req.user.email]);
      const authuser = result.rows[0];
      res.render("auth.ejs", {fname: authuser.firstname, lname: authuser.lastname, course: authuser.coursetitle, dateOfBirth: authuser.dateofbirth, email: authuser.email, address: authuser.address, city: authuser.city, state: authuser.state, country: authuser.country });
    } catch (err) {}
    
  } else {
    res.redirect("/")
  }

})


app.post("/enroll", async (req, res) => {
  const firstName = req.body.fname;
  const lastName = req.body.lname;
  const address = req.body.address;
  const city = req.body.city;
  const state = req.body.state;
  const country = req.body.country;
  const gender = req.body.sex;
  const dateOfBirth = req.body.dob;
  const pinCode = req.body.pincode;
  const courseTitle = req.body.coursetitle;
  const email = req.body.username;
  const password = req.body.password;
  const password2 = req.body.pwd2;

  if (password !== password2) {
    res.send("Password does not match");
  }

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      const result = await db.query(
        "INSERT INTO users (firstname, lastname, address, city, state, country, gender, dateofbirth, pincode, coursetitle, email, password, password2) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING *",
        [firstName, lastName, address, city, state, country, gender, dateOfBirth, pinCode, courseTitle, email, password, password2]
      );
      const user = result.rows[0];
      req.login(user, (err) => {
        console.log(err)
        res.redirect("/")
      })
    };
  } catch (err) {
    console.log(err);
  }
});

app.post("/password", async (req, res) => {
  if (req.user.password === req.body.oldpass) {
    if (req.body.newpass === req.body.newpass2) {
      await db.query("UPDATE users SET password = $1 WHERE email = $2", [req.body.newpass, req.user.email]);
      res.send("Password Changed Successfully")
    } else {
      res.send("New Password does not match")
    }
    
  } else {
    res.send("Old Password does not match")
  }

});




app.post("/login", passport.authenticate("local", {
  successRedirect: "/auth",
  failureRedirect: "/"
}));
 

passport.use(new Strategy(async function verify(username, password, cb) {

  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      username,
    ]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedPassword = user.password;

      if (password === storedPassword) {
        return cb(null, user)
      } else {
        return cb(null, false)
      }
    } else {
      return cb("User not Found")
    }
  } catch (err) {
    return cb(err);
  }

}));

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});


app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

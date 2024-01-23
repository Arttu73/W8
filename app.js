const express = require('express')
const app = express()
const port = 3000
const mongoDB = "mongodb://127.0.0.1:27017/testdb";
const mongoose = require("mongoose");
const User = require('./models/user.js');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cookieParser = require('cookie-parser')
const bcrypt = require('bcrypt');
const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const { check, validationResult } = require('express-validator');
const Todo = require('./models/todo.js');
dotenv.config();

var opts = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.SECRET
};


passport.use(new JwtStrategy(opts, async function(jwt_payload, done) {
    try {
        console.log("Passport user")
        const user = await User.findOne({email: jwt_payload.email})
        if (user) {
            console.log("Passport Found User")
            return done(null, user);
        } else {
            console.log("Passport NOT User")
            return done(null, false);
        }
    } catch (error) {
        console.log("Passport ERROR")
        return done(error, false);
    }
}));

app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser());

mongoose.connect(mongoDB);
mongoose.Promise = global.Promise;
const db = mongoose.connection;

db.on("error", console.error.bind(console, "MongoDB connection error"));

db.once('open', async () => {
    console.log('Connected to MongoDB');
});

app.use(passport.initialize());

app.post('/api/user/register', [
    check('email').isEmail(),
    check('password').isStrongPassword(),
    ], async (req, res) => {
  
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    console.log("registering")
    try {
        const email = req.body.email;
        const password = req.body.password;
        const existingUser = await User.findOne({ email });
        if(existingUser) {
            return res.status(403).json("User already exists!")
        }
        const newUser = new User({ email, password });
        await newUser.save();
        return res.status(200).json({ message: 'User registered successfully' });
    } catch {
        return res.status(404).json("An error has occurred")
    }    
});

app.post('/api/user/login', async (req, res) => {
    console.log("logging in")
    try {
        const email = req.body.email;
        const password = req.body.password;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: 'Invalid email' });
        } else {
            console.log("User found")

            try {
                if (await bcrypt.compare(password, user.password)) {
                    console.log("password matched")
                    const token = jwt.sign({id: user._id, email: user.email }, process.env.SECRET, { expiresIn: '1200' });
                    return res.json({success: true, token: token });
                } else {
                    console.log("Password did not match");
                    return res.status(401).json("Bad credentials :'(")
                }
            } catch {
                return res.status(404).json("An error has occurred")
            }
        }
    } catch {
        return res.status(500).json("An error has occurred")
    }    
});

app.get('/api/private', passport.authenticate('jwt', { session: false }), (req, res) => {
    return res.json({ email: req.user.email });
});

app.post('/api/todos', passport.authenticate('jwt', { session: false }), async (req, res) => {
    console.log("Adding todos")
    const user = req.user;
    const items = req.body.items;
    try {
        const existingTodos = await Todo.findOne({ user });
        if(existingTodos) {
            console.log("Existing todos");
            for(const item of items) {
                existingTodos.items.push(item);
            }
            await existingTodos.save();
            console.log("Existing todos saved");
            return res.status(200).json({ message: 'New todos added to existing todos' });
        } else {
            console.log("New todos");
            const newTodos = new Todo({ user, items });
            await newTodos.save();
            console.log("New todos saved");
            return res.status(200).json({ message: 'New Todos added' });
        }
    } catch {
        return res.status(500).json("An error has occurred")
    }  
});


app.listen(port, () => {
    console.log("Server is up and running at http://localhost:" + port)
})

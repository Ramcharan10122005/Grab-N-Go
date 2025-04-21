import express from "express";
import connectDB from "./db.js";
import path from "path";
import Register from "./models/registerSchema.js";
import session from "express-session"

const app = express();
const port = 3000;

connectDB();

app.set("view engine", "ejs");

app.set("views", path.join(process.cwd(), "views"));

app.use(express.static(path.join(process.cwd(), "public")));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.get("/", (req, res) => {
    res.render("index");
});

app.get('/login', (req, res) => {
    res.render('login')
})

app.use(session({
    secret: "your_secret_key",
    resave: false,
    saveUninitialized: true,
}));

app.get("/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send("Error logging out");
        }
        res.redirect("/");
    });
});

app.post('/login', async (req, res) => {
    try {
        const user = await Register.findOne({ username });

        if (!user) {
            return res.status(404).send("User not found");
        }

        if (user.password !== password) {
            return res.status(401).send("Invalid password");
        }

        res.status(200).send(`Welcome, ${user.name}!`);
        req.session.user = {
            id: user._id,
            username: user.username,
            role: user.role,
        };
    } catch (err) {
        res.status(500).send("Server error");
    }
});

app.get('/register', (req, res) => {
    res.render('register')
})

app.post("/register", async (req, res) => {
    const { name, email, username, password } = req.body;

    try {
        const hashedpassword = await bcrypt.hash(password, 10);
        const newUser = new Register({
            name,
            email,
            sername,
            password : hashedpassword
        })
        await newUser.save();
        res.send("Registration successful!");
    } catch (err) {
        console.error(err);
        res.status(500).send("Registration failed.");
    }
});


app.listen(port, () => {
    console.log("Server connected to port:", port);
});

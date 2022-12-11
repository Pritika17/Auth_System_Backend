require('dotenv').config()
require("./config/database").connect()
const express = require("express")
const jwt = require("jsonwebtoken")
const bcrypt = require("bcryptjs")
var cookieParser = require('cookie-parser')

// custom middleware
const auth = require("./middleware/auth")

// import model - User
const User = require("./model/user")
const user = require("./model/user")

const app = express()
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(cookieParser())

app.get("/", (req, res) => {
    res.send("Hello auth system")
})

app.post("/register", async (req, res) => {
    try {
        // collecting info from frontend
        const { firstname, lastname, email, password } = req.body

        // validate the data, if exists
        if (!(email && password && firstname && lastname)) {
            res.status(401).send("All fields are required")
        }

        // check if user exist
        const existingUser = await User.findOne({ email })
        if (existingUser) {
            res.status(401).send("User already exist")
        }

        // Encrypt the password
        const myEncryptedPassword = await bcrypt.hash(password, 10)

        // create a new entry to the database
        const user = await User.create({
            firstname,
            lastname,
            email,
            password: myEncryptedPassword
        })

        // create a token and send it to user
        const token = jwt.sign({
            id: user._id, email
        }, process.env.SECRET, { expiresIn: '2h' })

        user.token = token
        // don't want to send the password
        user.password = undefined

        res.status(201).json(user)

    } catch (error) {
        console.log(error)
        console.log("Error in response route")
    }
})

app.post("/login", async (req, res) => {
    try {
        // collect information from frontend
        const { email, password } = req.body

        //validate
        if (!(email && password)) {
            res.status(401).send("email & password are required")
        }

        // check user in database
        const user = await User.findOne({email})

        // if user does not exist
        if (!user) {
            res.status(401).send("This user does not exist")
        }

        // match the password
        if(user && (await bcrypt.compare(password, user.password))){
            const token = jwt.sign({id: user._id, email}, process.env.SECRET, {expiresIn: '2h'})

            user.password = undefined
            user.token = token

            const options = {
                expires: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
                httpOnly: true 
            }
            res.status(200).cookie("token", token, options).json({
                success: true,
                token,
                user
            })
        }
        res.status(400).send("email or password is incorrect")

    } catch (error) {
        console.log(error);
    }
})

app.get("/dashboard", auth, (req, res) => {
    res.send("Welcome to dashboaard")

})

app.get("/profile", (req, res) => {
    // access to req.user = id, email

    // based on id, query to DB and get all information of user - findone({id})

    // send a json response with all data
})

module.exports = app
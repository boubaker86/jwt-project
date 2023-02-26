require("dotenv").config();
var bcrypt = require('bcryptjs');
var jwt = require('jsonwebtoken');
require("./config/database").connect();
const express = require("express");
const auth = require("./middleware/auth");

const app = express();

app.use(express.json());

// importation du contexte utilisateur
const User = require("./model/user");

app.all("/welcome", auth, (req, res) => {
    res.status(200).send("Welcome 🙌 ");
  });

// Login
app.post("/login", async (req, res) => {
    // notre logique de connexion va ici
    try {
        // Obtenir l'entrée de l'utilisateur
        const { email, password } = req.body;

        // Valider la saisie de l'utilisateur
        if (!(email && password)) {
            res.status(400).send("Tous les champs sont obligatoires");
        }
        // Valider si l'utilisateur existe dans notre base de données
        const user = await User.findOne({ email });

        if (user && (await bcrypt.compare(password, user.password))) {
            // Create token
            const token = jwt.sign(
                { user_id: user._id },
                process.env.TOKEN_KEY,
                {
                    expiresIn: "2h",
                }
            );

            // save user token
            user.token = token;

            // user
            res.status(200).json(user);
        }else{
            res.status(400).send("Invalid Credentials");
        }
    } catch (err) {
        console.log(err);
    }
    // Notre logique de connexion se termine ici
});

// Register
app.post("/register", async (req, res) => {

    // Notre logique de registre commence ici
    try {
        // Obtenir l'entrée de l'utilisateur
        const { first_name, last_name, email, password } = req.body;

        // Valider la saisie de l'utilisateur
        if (!(email && password && first_name && last_name)) {
            res.status(400).send("Tous les champs sont obligatoires");
        }

        // vérifier si l'utilisateur existe déjà
        const oldUser = await User.findOne({ email });

        if (oldUser) {
            return res.status(409).send("L'utilisateur existe déjà. Veuillez vous connecter");
        }

        //Crypter le mot de passe de l'utilisateur
        encryptedPassword = await bcrypt.hash(password, 10);

        // Créer un utilisateur dans notre base de données
        const user = await User.create({
            first_name,
            last_name,
            email: email.toLowerCase(), // convertir les e-mails en minuscules
            password: encryptedPassword,
        });

        // Create token
        const token = jwt.sign(
            { user_id: user._id },
            process.env.TOKEN_KEY,
            {
                expiresIn: "2h",
            }
        );

        // save user token
        user.token = token;

        // return new user
        res.status(201).json(user);
    } catch (err) {
        console.log(err);
    }
    // Notre logique de registre s'arrête ici
});

module.exports = app;
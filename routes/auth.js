const router = require('express').Router();
const bcrypt = require('bcryptjs');
const User = require('../model/User');
const jwt = require('jsonwebtoken');
const verify = require('./verifyToken');
const {registerValidation, loginValidation} = require('../validations');

// register endpoint
router.post('/register', verify, async(req, res) =>{ 

    // validate data before creation of user
    const {error} = registerValidation(req.body);
    // check if registration has errors
    if(error) return res.status(400).send(error.details[0].message);

    // check if the user is already registered in the database
    const userExists = await User.findOne({email: req.body.email});
    // check if email exists
    if(userExists) return res.status(400).send('User already Exists');

    // generate salt
    const salt = await bcrypt.genSalt(10);
    // hash password
    const hashPassword = await bcrypt.hash(req.body.password, salt);


    // create new user
    const user = new User({
        name: req.body.name,
        email: req.body.email,
        password: hashPassword

    });

    // try to catch any errors registring a user
    try {
        const savedUser = await user.save();
        res.status(200).send({

            "Status": 200,
            "user_details": savedUser

        });

    } catch (error) {
        res.status(400).send(error);
    }

});


// login endpoint
router.post('/login', async (req, res) => {

    // validate data before creation of user
    const {error} = loginValidation(req.body);
    // check if registration has errors
    if(error) return res.status(400).send(error.details[0].message);

    // find if email exists in the database
    const user = await User.findOne({email: req.body.email});
    // check if email exists
    if(!user) return res.status(400).send('Incorrect email.');
    
    // check password if valid
    const validPass = await bcrypt.compare(req.body.password, user.password);
    if(!validPass) return res.status(400).send('Incorrect password.');

    //create and assign a token
    const token = jwt.sign({_id: user._id}, process.env.TOKEN_SECRET);
    res.header('auth-token', token).send(token);

});


module.exports = router;
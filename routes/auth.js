require('dotenv').config()

const router = require('express').Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken')
const mongoose = require('mongoose');
const User = require('../models/User.js')
const refreshToken = require('../models/refreshTokens.js')
const Joi = require('@hapi/joi');

// validators

const schemaRegister = Joi.object({
    name: Joi.string().min(6).max(255).required(),
    email: Joi.string().min(6).max(255).required().email(),
    phone: Joi.number().min(6).required(),
    password: Joi.string().min(6).max(1024).required(),
    username: Joi.string().min(6).max(255).required(),
    last_accesed_ip: Joi.string().min(6).max(255).required()
})

const schemaLogin = Joi.object({
    email: Joi.string().min(6).max(255).required().email(),
    password: Joi.string().min(6).max(1024).required()
})

// db connection
const uri = `mongodb+srv://${process.env.USER}:${process.env.PASSWORD}@${process.env.BDNAME}.qqshxbr.mongodb.net/?retryWrites=true&w=majority`

mongoose.connect(uri,
    { useNewUrlParser: true, useUnifiedTopology: true }
)
.then(() => console.log('Base de datos conectada'))
.catch(e => console.log('error db:', e))

// app routes

router.get('/dashboard',autheticateToken, async (req, res) => {
    res.json({
        error: null,
        data: {
            title: 'mi ruta protegida',
            user: req.user
        }
    })
})

router.post('/token', async (req, res) => {
    const reToken = req.body.token
    if (reToken == null) return res.sendStatus(401)
    const findtoken = await refreshToken.findOne({ token: reToken })
    if (!findtoken) return res.sendStatus(403);
    jwt.verify(reToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
      if (err) return res.sendStatus(403)
      const accessToken = createAccessToken({ name: user.name, _id: user._id })
      res.json({ accessToken: accessToken })
    })
})

router.delete('/logout', async (req, res) => {
    const deleted = await refreshToken.deleteOne({token: req.body.token})
    if(deleted) return res.sendStatus(204).json({
        message: "logged out"
    });
    res.sendStatus(500)
})

router.post('/register', async (req,res) => {

    // validate req.body
    const { error } = schemaRegister.validate(req.body)
    if(error){
        return res.status(400).json({
            error:error
        })
    } 

    // already registed?
    const isEmailExist = await User.findOne({ email: req.body.email });
    if (isEmailExist) {
    return res.status(400).json({error: "You're registed"})
    }   

    // hashing password
    const hashedPassword = await bcrypt.hash(req.body.password, 10)

    const user = new User({
        name: req.body.name,
        email: req.body.email,
        phone: req.body.phone,
        password: hashedPassword,
        username: req.body.username,
        last_accesed_ip: req.body.last_accesed_ip
    });
    try {
        const savedUser = await user.save();
        res.json({
            error:null,
            data: savedUser
        })
    } catch (error){
        res.status(500).json({error:error})
    }
})

router.post('/login', async (req, res) => {
    
    // authenticate user

    // validations
    const { error } = schemaLogin.validate(req.body);
    if (error) return res.status(400).json({ error: error.details[0].message })
    
    const user = await User.findOne({ email: req.body.email });
    if (!user) return res.status(400).json({ error: 'User not registed' });

    const validPassword = await bcrypt.compare(req.body.password, user.password);
    if (!validPassword) return res.status(400).json({ error: 'contraseña no válida' })
    
    try {
        if(validPassword) {

            const Token = createAccessToken(user)
            const reToken = jwt.sign({
                user: user.name,
                _id: user._id
            }, process.env.REFRESH_TOKEN_SECRET)
            
            const retoken = new refreshToken({
                token: reToken
            })

            const savedReToken = await retoken.save()

            res.header('auth-token',Token).json({
                "error": null,
                "messaje": "welcome",
                "data": {
                    access: {Token},
                    refresh: {savedReToken}
                }
            })

        } else {
            res.send('Not Allowed')
        }
    } catch {
        res.status(500).send()
    }
})


// handling tokens

function createAccessToken(user){
    return jwt.sign({user: user.name, _id:user._id}, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '5d' })    
}


function autheticateToken(req, res, next){
    const token = req.header('auth-token')
    if (!token) return res.status(401).json({error: 'denied'});
    try{
        const verified = jwt.verify(token,process.env.ACCESS_TOKEN_SECRET)
        req.user = verified
        next() // continue
    }catch (error){
        res.status(400).json({error: "token invalid"})
    }
} 

module.exports = router;

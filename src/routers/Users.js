const express = require('express');
const crypto = require('crypto');
const sharp = require('sharp')
const multer = require('multer')
const _ = require('lodash')
const jwt = require('jsonwebtoken')
const User = require('../Model/UserModel');
const auth = require('../middleware/auth')
const { verificationEmail, sendWelcomeEmail, sendEmailCancelation } = require('../services/emailVerify')
const { sendPasswordEmailChange } = require('../services/passwordchange')
const router = new express.Router()
const { userRegistration, userLogin, userCount, forgotPassword, resetPassword } = require('../controllers/userRoleAuth');
const e = require('express');
const { post } = require('../routes');


// creating the user 
router.post('/sign-up', async (req, res)=>{
    await userRegistration(req.body, 'users', res)
});

// admin registration 
router.post('/admin-sign-up', async(req, res)=>{
    await userRegistration(req.body, 'admin', res)
})

// route to verify email
router.get('/verify-email', async(req, res)=> {

    try {
        const verifiedToken = req.query.token
    
        console.log(verifiedToken,'.......................................')
    
        const user = await User.findOne({emailToken: verifiedToken});
        if(!user) {
            res.status(404).json({
            message: 'token does not exist'
            })
        }
        else{
            user.emailToken = null
            user.isVerified = true

            await user.save()
            sendWelcomeEmail(user.email, user.username)
            res.status(200).json({"message": "Email confirmed"})
            console.log('welcome email has been sent')
        }

        
    }catch(e) {
        res.status(400).json({"message":'user with token does not exist', "error": e})
    }


})

// user forgot-password route
router.post('/forgot-password', async (req, res, next)=>{
    await forgotPassword(req.body, res)
})

// password reset link
router.post('/reset-password', async (req, res)=> {
    await resetPassword(req.body, res)
})

// login user
router.post('/login', async(req, res) => {
    await userLogin(req.body, 'users', res)
})
// login user(admin route)
router.post('/login-admin',  async (req, res)=> {
    await userLogin(req.body, 'admin', res)
})

// user(users  and admin viewing their profile)
router.get('/me', auth, async (req, res) => {
    res.status(200).json
    ({
        profile: req.user,
        message: 'view your profile',
        success: true
    })
})

// admin getting total amount of users
router.get('/get-all-users', auth, async(req, res)=>{
    await userCount('admin', res)
})

// User logout
router.post('/me/logout', auth, async(req, res)=> {
    try{
        req.user.tokens = req.user.tokens.filter((token) => {
            return token.token != req.token
        })

        await req.user.save()
        sendEmailCancelation(req.user.email, req.user.username)
        res.send({
            message: 'logout successfully'
        })

    }catch(e) {
        res.status(500).send(e)
    }
})

// logout user from every device
router.post('/me/logoutall', auth, async(req, res)=> {
    try{
        req.user.tokens =req.user.tokens.filter((token)=> delete token)
        req.user.save()
        sendEmailCancelation(req.user.email, req.user.username)
        res.status(200).json({
            message: 'logged out from all devices'
        })
    }catch(e) {
        res.send(e)
    }
})

// profile update route
router.patch('/me/update', auth, async (req, res)=>{
    const updates = Object.keys(req.body)
    const allowableupdate = ['username', 'email', 'password']
    const isValidUpdate = updates.every((update)=> allowableupdate.includes(update));

    if(!isValidUpdate) {
        return res.status(400).json({"error": 'invalid parameter to update'})
    }

    try{
        updates.forEach((update)=> req.user[update] = req.body[update] )
        req.user.confirmPassword = req.user.password
        await req.user.save()

        res.status(200).send(req.user)
    }catch(e) {
        console.log(e)
        res.status(400).json({
            "message": "failed to update"
        })
    }
})


/**
 * 
 * @desc serving up the profile picture 
 */

//  setting profile restriction
const upload = multer({
    limits: {
        fileSize: 2000000
    },

    fileFilter(req, file, cb) {
       if(!file.originalname.match(/\.(jpg|jpeg|png|svg)$/gm)){
           cb(new Error('file format is not accepted'))
       }

       cb(undefined, true)
    }
})

// creating the user profile picture
router.post('/me/avatar', auth, upload.single('avatar'), async (req, res)=> {
    const buffer = await sharp(req.file.buffer).resize({ width:350, height: 350}).png().toBuffer()
    req.user.avatar = buffer;

    await req.user.save()
    res.json({
        success: true
    })
}, (error, req, res, next) => {
    res.status(400).json({
        error: error.message
    })
})

// serving the profile picture
router.get('/:id/avatar', async (req, res)=> {
    try{
        const user = await User.findById(req.params.id)

        if(!user || !user.avatar) {
            throw new Error('user does not exist or does not have access to an avatar')
        }

        res.set('Content-Type', 'image/png')
            res.status(200).send(user.avatar)
    }catch(e) {
        res.status(400).json({
            message:'unable to serve up profile picture'
        })
    }
}, (error,req, res, next)=> {
    res.status(400).json({
        error: error.message
    })
})

// deleting profile picture
router.delete('/me/avatar', auth, async (req, res)=> {
    req.user.avatar = null
    await req.user

    res.status(200).json({
        message:'profile picture has been deleted successfully',
        success: true
    })
}, (e, req, res, next)=> {
    res.status(400).json({
        error:e.message
    })
})

// deleting a user
router.delete('/users/me', auth,  async  (req, res)=> {
    try{
        await req.user.remove()
        res.send(req.user)
    } catch (e) {
        res.status(500).send()
    }
})

// getting one user from the userbase:
router.get('/user', async(req, res)=> {
    try{
        const Userarray = []
        const user = await User.find({})
        Userarray.push(user)

        const randomUser = Math.floor(Math.random() * Userarray.length)

        res.status(200).json({
            user: Userarray[randomUser],
            success: true
        })
    }catch(e) {
        res.status(400).json({
            success: false,
            message: 'can not filter the array'
        })
    }

    
})


// exporting the routes
module.exports = router
const express = require('express');

const router = express.Router();


router.get('/' , (req,res)=>{
    res.render('index.hbs')
})
router.get('/about', (req,res)=>{
    res.render('about.hbs');
})
router.get('/register' , (req,res)=>{
    res.render('register.hbs')
})
router.get('/login',(req,res)=>{
    res.render('login.hbs')
})
router.get('/home' ,(req,res)=>{
    if(req.session.userId){
        return res.render('home.hbs');
    }
    res.redirect('/');
})

router.get('/resume',(req,res)=>{
    if(req.session.userId){
        return res.render('resume.hbs');
    }
    res.redirect('/');
})
router.get('/logout' , (req,res)=>{
    // res.clearCookie('jwt');
    req.session.destroy();
    res.redirect('/');
})

router.get('*',(req,res)=>{
    res.redirect('/')
})
module.exports = router;
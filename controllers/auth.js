const  mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const app = require('express');
// const session = require('express-session')
const  db = mysql.createConnection({
    host: process.env.DATABASE_HOST,
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
    database:process.env.DATABASE
  });
 
exports.register = (req,res)=>{
    const {name, email, password , cpassword} = req.body;
    db.query("SELECT * FROM users WHERE email = ?",[email] ,async (error,result)=>{
        if(error) throw error;
        if(result.length > 0){
            return res.render('register.hbs' ,{
                message:'That email is alreay in use'
            });
        }else if(password !== cpassword){
            return res.render('register.hbs' , {
                message:'Password does not match!'
            });
        }

        let hashedPassword = await bcrypt.hash(password , 8);
        console.log(hashedPassword);

        db.query("INSERT INTO users SET ? " , {name:name , email:email , password : hashedPassword} , (errr,result)=>{
            if(errr){
                console.log(errr);
            }else{
                console.log(result);
                return res.render('register.hbs' , {
                    message:'User Registered'
                })
            }
        })
    })
}

exports.login = async (req,res) =>{
    try{
        const {email , password} = req.body;
        if(!email || !password){
            return res.status(400).render('login.hbs' , {
                message:'Please provide an email and password!'
            })
        }
            db.query("SELECT * FROM users WHERE email = ?" , [email],async (err,result)=>{
                
                if(!result || !(await bcrypt.compare(password , result[0].password))){
                    return res.status(401).render('login.hbs' , {
                        message:'Email or Password incorrect'
                    });
                }
                else{
                    const id = result[0].id ;
                    console.log(id);
                    req.session.userId = id;
                    console.log(req.session.userId);
                    // user.session.user = id;
                    // console.log(user.session.user);
                    // const token = jwt.sign({id} , process.env.JWT_SECRET , {
                    //     expiresIn:process.env.JWT_EXPIRES_IN
                    // })

                    // const cookieOptions = {
                    //     expires:new Date(
                    //         Date.now() + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000
                    //     ),
                    //     httpOnly:true
                    // }

                    // res.cookie('jwt' , token , cookieOptions);
                    if(req.session.userId){
                        res.status(200).redirect('/home')
                    }else{
                        res.redirect('/login')
                    }
                }
            })
        
    }catch(err){
        console.log(err);
    }
  
}

// app.get('/logout', (req, res) => {
//     res.clearCookie('token');
//     return res.redirect('/');
//   });



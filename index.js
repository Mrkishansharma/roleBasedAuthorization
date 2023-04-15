
const express = require('express');

const { connection } = require('./db');

require('dotenv').config()

const app = express();


const bcrypt = require('bcrypt');

const jwt = require('jsonwebtoken');

const { UserModel } = require('./models/user.model');

const {auth} = require('./middlewares/auth')

const { verifyRole} = require('./middlewares/verifyRole')

const cookieParser = require('cookie-parser')

app.use(cookieParser());




// blacklist DB

const blacklistedToken = []


app.use(express.json());


app.post('/register', async (req, res)=>{

    const { pass, email } = req.body;

    try {

        const userPresent = await UserModel.find({email}).count();

        if(userPresent){
            return res.status(400).send({"msg":"user already exits"});
        }

        const hashPassword = bcrypt.hashSync(pass, 5);

        const newUser = new UserModel( { ...req.body, pass : hashPassword } );

        await newUser.save();

        return res.status(200).send({msg:"register successfull", user : newUser})

    } catch (error) {
        
        res.status(500).send({eroor:error.message})

    }
})


app.post('/login', async (req, res)=>{

    const { pass, email } = req.body;

    try {

        const userPresent = await UserModel.findOne({email});

        if(!userPresent){
            return res.status(400).send({"msg":"user doesn't exits"});
        }

        const verifyPass = bcrypt.compareSync(pass, userPresent.pass);

        if(!verifyPass){
            return res.status(400).send({
                msg:"Invalid Password"
            })
        }

        const token = jwt.sign( { email, role:userPresent.role }, process.env.secureKey, {expiresIn : "50m" })

        res.cookie( "TOKEN", token, { maxAge : 1000*5*60 } )

        return res.status(200).send({
            msg:"login successfull"
        })

    } catch (error) {
        
        res.status(500).send({eroor:error.message})

    }
})


app.get('/logout', async(req,res)=>{

    const { TOKEN } = req.cookies;

    blacklistedToken.push( TOKEN );

    return res.status(200).send({
        msg:"logout successfull"
    })

})






app.post('/createAccount', auth, verifyRole(['SupperAdmin', 'Admin']), async (req,res)=>{

    res.status(200).send({msg:'user created successfully'});
    
})


app.delete('/deleteAccount', auth, verifyRole(['SupperAdmin', 'Admin']), async (req,res)=>{

    res.status(200).send({msg:'user deleted successfully'});

})


app.get('/getuser', auth, verifyRole(['SupperAdmin', 'User']), async (req,res)=>{

    res.status(200).send({msg:'user details successfull'});

})


app.get('/report', auth, verifyRole(['SupperAdmin']), async (req,res)=>{

    res.status(200).send({msg:'reports'});

})






app.listen(3000, async ()=>{
    try {
        await connection 
        console.log('mongo connected');
    } catch (error) {
        console.log(error);
    }
    console.log('server is runinng');
})
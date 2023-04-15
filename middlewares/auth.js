

const jwt = require('jsonwebtoken');

require('dotenv').config();

const auth = async (req,res,next) => {
    
    const { TOKEN } = req.cookies;

    try {

        const tokenVerify = jwt.verify(TOKEN, process.env.secureKey);
    
        if(!tokenVerify){

            return res.status(400).send({msg:"Token is not valid"})
        }

        
        req.payload = tokenVerify;

        next()
        
    } catch (error) {
        
        res.status(500).send({eroor:error.message})

    }

}


module.exports = {
    auth
}
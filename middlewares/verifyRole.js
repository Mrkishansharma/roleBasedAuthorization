
const verifyRole = ( permitedRole ) => {

    return  (req,res,next) => {

        const {role} = req.payload;
    
        if(permitedRole.includes(role)){
    
            next();
    
        }else{
    
            return res.status(401).send( {msg : "Unauthorized access"} )
    
        }

    }

}

module.exports = {
    verifyRole
}
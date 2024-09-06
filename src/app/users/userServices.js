const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");
const { User } = require("../../models/users");

const createNewUser = async (userData) =>{
    const { email, fullName, password } = userData;
    const userExists = await User.findOne({ email: email.toLowerCase() });
    if(userExists){
        return "exists";
    }
    let hashedPassword = bcrypt.hashSync(password, 8);
    const addUser = await User.create({
        _id: uuidv4(),
        email: email.toLowerCase(), 
        fullName,
        phoneNumber, 
        password: hashedPassword,
        isVerified: 1
    })
    if(!addUser){
        return null;
    }
    return addUser;

};

const createNewUserGoogle = async (userData) =>{
    const { email, name } = userData;
    const userExists = await User.findOne({ email: email.toLowerCase() });
    if(userExists){
        return userExists;
    }
    if (userExists.lockUntil && userExists.lockUntil > Date.now()) return "locked";
    const addUser = await User.create({
        _id: uuidv4(),
        email: email.toLowerCase(), 
        fullName: name,  
        googleSignin: 1,
        isVerified: 1
    })
    if(!addUser){
        return null;
    }
    return addUser;

};


module.exports = {
    createNewUser,
    createNewUserGoogle
}
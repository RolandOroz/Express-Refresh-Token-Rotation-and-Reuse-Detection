const User = require("../model/User");
const bcrypt = require("bcrypt");


const handleNewUser = async (req, res) => {
    const { user, pwd } = req.body;
    if (!user || !pwd) return res.status(400).json({ "message": "Username and password are required!"});
    
    // Check for duplicate username in the DB
    const duplicateUsername = await User.findOne({ username: user }).exec();


    if (duplicateUsername) return res.sendStatus(409); //Conflict
    try {
        // Encrypt the password
        const hashPwd = await bcrypt.hash(pwd, 10);
        // Create and store new user
        const result = await User.create({ 
            "username": user,
            "password": hashPwd 
        });

        console.log(result);
        
        res.status(201).json({ "success": `New user ${user} created!` });        
    } catch (error) {
        res.status(500).json({ "message": error.message });
    }
}

module.exports = { handleNewUser }
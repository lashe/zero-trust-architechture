const { jsonFailed, jsonS } = require("../../utils");
const { createNewUser } = require("./userServices");

let controller = {
    signUp: async (req, res) => {
        const { email, fullName, phoneNumber, password } = req.body;
        if (!email) return jsonFailed(res, {}, "No email Provided", 400);
        const newUser = { email, fullName, phoneNumber, password };
        const createUser = await createNewUser(newUser);
        console.log({returnedData: createUser});
        if (!createUser) return jsonFailed(res, {}, "Error Creating New User", 400);
        if(createUser === "exists")return jsonFailed(res, {}, "An account already exists with this email", 400);
        return jsonS(res, 201, "Successfully Created User");
    }
};

module.exports = controller;
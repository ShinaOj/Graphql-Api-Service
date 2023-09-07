const User = require('../../models/users');
const { ApolloError } = require('apollo-server-errors');
const bcrypt = require("bcryptjs");
const jwt= require('jsonwebtoken');

module.exports = {
    Mutation: {
        async registerUser(_, {registerInput: {username, email, password} }) {
            // see if an old user exits with email attempting to sign up
            const oldUser = await User.findOne({email});

            if (oldUser){
                throw new ApolloError('A user is already registered with the email' + email, 'USER_ALREADY_EXISTS');



            }

            // throw error if user exists

            // encrypt password
            var encryptedPassword = await bcrypt.hash(password, 10);

            // build mongoose model for user
             const newUser = new User({
                username: username,
                email: email.toLowerCase(),
                password: encryptedPassword

             })

            // create jwt attached to user model
            const token= jwt.sign(
                { user_id: newUser._id, email },
                 'UNSAFE_STRING',
                {
                    expiresIn: "2h"
                }

            );

            newUser.token = token;

            // save user in mongodb

            const res = await newUser.save()

            return {
                id: res.id,
                ...res._doc
            };

                
        },
        async loginUser(_, {loginInput: { email, password} }) {
            // see if a user exist with the email
            const user = await User.findOne({email});

            // check if the password is equals encrypted password
            if (user && (await bcrypt.compare(password, user.password))){
                // create new token
                const token= jwt.sign(
                    { user_id: newUser._id, email },
                    'UNSAFE_STRING',
                    {
                        expiresIn: "2h"
                    }
    
                );
                // attach token to the user model

                user.token = token;

                return {
                    id: user.id,
                    ...user._doc
                };
            } else{
                // if user doesnt exist, return error
                 throw new ApolloError('Incorrect Password', 'INCORRECT_PASSWORD');

            }
    
        }
    },
    Query: {
         user: (_, {ID}) => User.findById(ID)
    }
}
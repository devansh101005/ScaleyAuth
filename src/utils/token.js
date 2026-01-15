import jwt from 'jsonwebtokens'

export const signAccessToken =(payload) => {
    return jwt.sign(payload, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN
    })
}

export const verifyAccessToken =(token) => {
    return jwt.verify(token, process.env.JWT_SECRET)
}
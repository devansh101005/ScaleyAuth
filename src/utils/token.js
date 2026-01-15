import jwt from 'jsonwebtokens'

export const signAccessToken =(payload) => {
    return jwt.sign(payload, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN
    })
}

export const verifyAccessToken =(token) => {
    return jwt.verify(token, process.env.JWT_SECRET)
}

export const signRefreshToken = (payload) =>
  jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN
  });

export const verifyRefreshToken = (token) =>
  jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
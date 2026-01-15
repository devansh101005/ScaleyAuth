import * as authService from "./auth.service.js";

export const register = async (req, res, next) => {
  try {
    const user = await authService.register(req.body);
    res.status(201).json(user);
  } catch (err) {
    next(err);
  }
};

export const login = async (req, res, next) => {
  try {
    const user = await authService.login(req.body);
    res.status(200).json(user);
  } catch (err) {
    next(err);
  }
};


export const refreshToken = async (req, res, next) => {
  try {
    const tokens = await authService.refresh({
      refreshToken: req.body.refreshToken
    });
    res.status(200).json(tokens);
  } catch (err) {
    next(err);
  }
};

export const logout = async (req, res, next) => {
  try {
    await authService.logout({
      refreshToken: req.body.refreshToken
    });
    res.status(204).send();
  } catch (err) {
    next(err);
  }
};


export const googleRedirect = (req, res) => {
  const redirectUrl =
    "https://accounts.google.com/o/oauth2/v2/auth" +
    "?client_id=" + process.env.GOOGLE_CLIENT_ID +
    "&redirect_uri=" + process.env.GOOGLE_CALLBACK_URL +
    "&response_type=code" +
    "&scope=email profile";

  res.redirect(redirectUrl);
};

export const googleCallback = async (req, res, next) => {
  try {
    const tokens = await authService.googleOAuth(req.query.code);
    res.json(tokens); // later: redirect with cookie
  } catch (err) {
    next(err);
  }
};



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

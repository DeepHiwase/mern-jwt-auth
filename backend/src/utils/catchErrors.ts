import { NextFunction, Request, Response } from "express";

type AcyncController = (
  req: Request,
  res: Response,
  next: NextFunction
) => Promise<any>;

const catchErrors =
  (controller: AcyncController): AcyncController =>
  async (req, res, next) => {
    try {
      await controller(req, res, next);
    } catch (err) {
      next(err);
    }
  };

export default catchErrors;

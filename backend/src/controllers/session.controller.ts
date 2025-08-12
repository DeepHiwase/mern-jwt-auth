import z from "zod";
import { NOT_FOUND, OK } from "../constants/http";
import SessionModel from "../models/session.model";
import catchErrors from "../utils/catchErrors";
import appAssert from "../utils/appAssert";

export const getSessionsHandler = catchErrors(async (req, res) => {
  const sessions = await SessionModel.find(
    {
      userId: req.userId,
      expiresAt: { $gt: new Date() },
    },
    {
      // get specific fields only so set 1 to those fields u want
      _id: 1,
      userAgent: 1,
      createdAt: 1,
    },
    {
      // get newest first -> sort
      sort: {
        createdAt: -1,
      },
    }
  );

  return res.status(OK).json(
    sessions.map((session) => ({
      ...session.toObject(),
      ...(session.id === req.sessionId && {
        isCurrent: true, // we are sending this as to to show current session can't be deleted at UI side so user can't delete it
      }),
    }))
  );
});

export const deleteSessionHandler = catchErrors(async (req, res) => {
  const sessionId = z.string().parse(req.params.id);
  const deleted = await SessionModel.findOneAndDelete({
    _id: sessionId,
    userId: req.userId, // so anyone can't hit delete session endpoint with random id in param
  });
  appAssert(deleted, NOT_FOUND, "Session not found");
  return res.status(OK).json({
    message: "Session removed",
  });
});

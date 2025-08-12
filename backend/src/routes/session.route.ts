import { Router } from "express";
import { deleteSessionHandler, getSessionsHandler } from "../controllers/session.controller";

const sessionRoutes = Router();

// prefix: /session
sessionRoutes.get("/", getSessionsHandler);
sessionRoutes.delete("/:id", deleteSessionHandler);

export default sessionRoutes;

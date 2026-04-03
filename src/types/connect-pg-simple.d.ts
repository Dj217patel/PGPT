declare module "connect-pg-simple" {
  import type session from "express-session";

  function connectPgSimple(session: typeof session): any;

  export = connectPgSimple;
}

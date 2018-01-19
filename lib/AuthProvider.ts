import * as eta from "../eta";
import * as db from "../db";
import * as passport from "passport";

export default class AuthProvider {
    public config: eta.Configuration;
    public db: db.RepositoryManager;
    public buildStrategy(): passport.Strategy { return undefined; }
    public beforeLogin(http: eta.HttpRequest): Promise<void> { return Promise.resolve(); }
    public onLogin(http: eta.HttpRequest, user: db.User): Promise<void> { return Promise.resolve(); }
}

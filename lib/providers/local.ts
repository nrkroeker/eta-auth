import * as eta from "../../eta";
import * as db from "../../db";
import * as passport from "passport";
import AuthProvider from "../AuthProvider";
import { Strategy } from "passport-local";

export default class LocalProvider extends AuthProvider {
    public buildStrategy(): passport.Strategy {
        return new Strategy((username: string, password: string, done: (err: Error, user?: db.User) => void) => {
            db.localAuthAccount().createQueryBuilder("account")
                .leftJoinAndSelect("account.user", "user")
                .where(`"user"."username" = :username`, { username })
                .getOne()
            .then(account => {
                if (account === undefined) return done(undefined, undefined);
                return done(undefined, account.verifyPassword(password) ? account.user : undefined);
            }).catch(err => done(err));
        });
    }

    public async beforeLogin(http: eta.HttpRequest): Promise<void> {
        if (http.req.method !== "GET") return;
        if (http.req.session.lastPage) {
            http.req.session.authFrom = http.req.session.lastPage;
            await eta.session.save(http.req.session);
        }
        eta.IRequestHandler.redirect(http.res, "/auth/local/login");
    }
}

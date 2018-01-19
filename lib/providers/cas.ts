import * as eta from "../../eta";
import * as db from "../../db";
import * as passport from "passport";
import AuthProvider from "../AuthProvider";
const Strategy = require("passport-cas2").Strategy;

export default class CasProvider extends AuthProvider {
    public buildStrategy(): passport.Strategy {
        return new Strategy({
            casURL: this.config.get("modules.cre-auth.providers.cas.url")
        }, (username: string, profile: CasProfile, done: (err: Error, user?: db.User) => void) => {
            this.db.user.findOne({ username })
                .then(user => done(undefined, user || <any>{ username }))
                .catch(err => done(err));
        });
    }

    public async onLogin(http: eta.HttpRequest, user: db.User): Promise<void> {
        if (user.id !== undefined) { // User already exists in DB
            return;
        }
        http.req.session["auth.cas.username"] = user.username;
        await eta.session.promise(http.req.session, "save");
        eta.IRequestHandler.redirect(http.res, "/auth/cas/register");
    }
}

interface CasProfile {
    provider: string;
    id: string;
    displayName: string;
    name: {
        familyName: string;
        givenName: string;
        middleName: string;
    };
    emails: string[];
    safeword: string[];
    passphrase: string[];
}

import * as eta from "../../../eta";
import * as db from "../../../db";
import * as querystring from "querystring";
import Seeder from "../../../../cre-db-shared/lib/Seeder";

@eta.mvc.route("/api/auth/local")
@eta.mvc.controller()
export default class ApiAuthLocalController extends eta.IHttpController {
    @eta.mvc.raw()
    @eta.mvc.post()
    public async login({ username, password }: { username: string, password: string }): Promise<void> {
        const account: db.LocalAuthAccount = await db.localAuthAccount().createQueryBuilder("account")
            .leftJoinAndSelect("account.user", "user")
            .where("user.username = :username", { username })
            .getOne();
        if (!account) {
            eta.logger.obj(username);
            this.redirect("/auth/local/login?error=Invalid%20login");
            return;
        }
        const hashed: string = eta.crypto.hashPassword(password, account.salt);
        if (hashed !== account.password) {
            this.redirect("/auth/local/login?error=Invalid%20login");
            return;
        }
        this.req.session.userid = account.user.id;
        if (!this.req.session.authFrom) this.req.session.authFrom = "/home/index";
        await this.saveSession();
        if (account.shouldForceReset) {
            this.req.session.beforeAuth = this.req.session.authFrom;
            await this.saveSession();
            this.redirect("/auth/local/changePassword?error=" + querystring.escape("You must change your password before logging in."));
        } else {
            this.redirect(this.req.session.authFrom);
        }
    }

    @eta.mvc.raw()
    @eta.mvc.post()
    public async register(params: Partial<db.User> & { password: string }): Promise<void> {
        const user: db.User = db.user().create(params);
        await db.user().save(user);
        const salt: string = eta.crypto.generateSalt();
        const hashed: string = eta.crypto.hashPassword(params.password, salt);
        await db.localAuthAccount().save(db.localAuthAccount().create({
            password: hashed,
            salt,
            user
        }));
        this.redirect("/auth/local/login?success=Successfully%20registered.");
    }

    @eta.mvc.raw()
    @eta.mvc.post()
    @eta.mvc.authorize()
    public async changePassword({ oldPassword, newPassword }: { oldPassword: string, newPassword: string }): Promise<void> {
        const account: db.LocalAuthAccount = await db.localAuthAccount().createQueryBuilder("account")
            .where(`"account"."userId" = :userId`, { userId: this.req.session.userid })
            .getOne();
        if (!account) {
            return this.redirect("/auth/local/changePassword?error=Something%20went%20wrong.");
        } else {
            this.req.session.authFrom = this.req.session.beforeAuth;
            await this.saveSession();
        }
        const hashed: string = eta.crypto.hashPassword(oldPassword, account.salt);
        if (hashed !== account.password) {
            return this.redirect("/auth/local/changePassword?error=Password%20incorrect.");
        }
        account.shouldForceReset = false;
        account.salt = eta.crypto.generateSalt();
        account.password = eta.crypto.hashPassword(newPassword, account.salt);
        await db.localAuthAccount().save(account);
        this.redirect("/auth/local/login?success=Successfully%20changed%20password.");
    }

    @eta.mvc.flags(["seed"])
    @eta.mvc.raw()
    @eta.mvc.authorize(["all"])
    @eta.mvc.get()
    public async seed(seeder: Seeder): Promise<void> {
        if (!seeder) return;
        const salt: string = eta.crypto.generateSalt();
        const password: string = eta.crypto.hashPassword("user", salt);
        await seeder.seed(db.localAuthAccount(), seeder.rows.User.map(user =>
            db.localAuthAccount().create({ user, salt, password })
        ), `"userId"`);
    }
}

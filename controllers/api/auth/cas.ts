import * as eta from "../../../eta";
import * as db from "../../../db";

@eta.mvc.route("/api/auth/cas")
@eta.mvc.controller()
export default class ApiAuthCasController extends eta.IHttpController {
    @eta.mvc.raw()
    @eta.mvc.post()
    public async register({ firstName, lastName, email }: { firstName: string, lastName: string, email: string }): Promise<void> {
        if (!this.req.session["auth.cas.username"]) {
            this.res.statusCode = eta.constants.http.AccessDenied;
            return;
        }
        let user: db.User = await this.db.user.findOne({ username: this.req.session["auth.cas.username"] });
        if (user) {
            return this.redirect("/login");
        }
        user = this.db.user.create({
            firstName, lastName, email,
            username: this.req.session["auth.cas.username"]
        });
        await this.db.user.save(user);
        this.redirect("/login");
    }
}

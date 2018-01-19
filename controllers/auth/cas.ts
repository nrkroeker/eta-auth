import * as eta from "../../eta";
import * as db from "../../db";

@eta.mvc.route("/auth/cas")
@eta.mvc.controller()
export default class AuthCasController extends eta.IHttpController {
    @eta.mvc.get()
    public async register(): Promise<void> {
        if (this.config.get("auth.provider") !== "cas") {
            this.res.statusCode = eta.constants.http.AccessDenied;
        }
    }
}

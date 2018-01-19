import * as db from "../db";
import * as eta from "../eta";
import * as fs from "fs-extra";
import * as passport from "passport";
import Application from "../../../server/Application";
import AuthProvider from "../lib/AuthProvider";
const CasStrategy = require("passport-cas2").Strategy;

export default class PassportLifecycle extends eta.ILifecycleHandler {
    private app: Application;
    private providers: {[key: string]: AuthProvider} = {};

    public register(app: Application): void {
        this.app = app;
        this.app.server.on("start", this.onAppStart.bind(this));
    }

    private async onAppStart(): Promise<void> {
        const hosts = Object.keys(this.app.configs).filter(k => k !== "global");
        for (const host of hosts) {
            const providerName: string = this.app.configs.global.get("auth.provider");
            const providerPath: string = eta.constants.modulesPath + "/cre-auth/lib/providers/" + providerName + ".js";
            if (!await fs.pathExists(providerPath)) return; // provider may be initialized in another module
            const authProvider: typeof AuthProvider = require(providerPath).default;
            if (authProvider === undefined) return eta.logger.error("Authentication provider " + providerName + " has no default export.");
            this.providers[host] = new authProvider();
            this.providers[host].db = new db.RepositoryManager(host);
            this.providers[host].config = this.app.configs[host];
            const strategy = this.providers[host].buildStrategy();
            passport.use(host + "-" + strategy.name, strategy);
        }
        this.app.server.on("pre-auth", this.onPreAuth.bind(this));
        this.app.server.on("auth", this.onAuth.bind(this));
    }

    private async onPreAuth(http: eta.HttpRequest): Promise<void> {
        await this.providers[http.req.hostname].beforeLogin(http);
    }

    private async onAuth(http: eta.HttpRequest, user: db.User): Promise<void> {
        await this.providers[http.req.hostname].onLogin(http, user);
        if (!http.res.finished) http.req.session.userid = user.id;
    }
}

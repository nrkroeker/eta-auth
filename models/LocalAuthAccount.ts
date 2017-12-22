import * as orm from "typeorm";
import * as eta from "../eta";
import User from "../../cre-db-shared/models/User";

@orm.Entity()
export default class LocalAuthAccount {
    @orm.PrimaryColumn()
    public userId: number;

    @orm.JoinColumn()
    @orm.OneToOne(t => User, { nullable: false })
    public user: User;

    @orm.Column({ type: "varchar", nullable: false })
    public password: string;

    @orm.Column({ type: "varchar", nullable: false })
    public salt: string;

    @orm.Column({ type: "boolean", nullable: false, default: "f", name: "should_force_reset" })
    public shouldForceReset = false;

    public toCacheObject(): any {
        return {
            userId: this.user.id,
            password: this.password,
            salt: this.salt,
            should_force_reset: this.shouldForceReset
        };
    }

    // stop-generate
    public verifyPassword(password: string): boolean {
        const hash: string = eta.crypto.hashPassword(password, this.salt);
        return hash === password;
    }
}

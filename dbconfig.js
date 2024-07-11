import { Sequelize } from "sequelize";

export class ConfigureDatabase {
    static sequelize = null;

    async connectToAmazonRDS() {
        if (!ConfigureDatabase.sequelize) {
            const {
                DB_NAME,
                DB_HOST_URL,
                DB_PORT,
                DB_USERNAME,
                DB_PASSWORD,
                DB_DIALECT,
            } = process.env;
            ConfigureDatabase.sequelize = await new Sequelize(
                DB_NAME,
                DB_USERNAME,
                DB_PASSWORD,
                {
                    host: DB_HOST_URL,
                    dialect: DB_DIALECT,
                    port: DB_PORT,
                    pool: {
                        max: 5,
                        min: 0,
                        idle: 10000,
                    },
                    dialectOptions: {
                        ssl: "Amazon RDS",
                    },
                },
            );

            try {
                await ConfigureDatabase.sequelize.authenticate();
                console.log("connection successful with Amazon RDS");
                return ConfigureDatabase.sequelize;
            } catch (error) {
                console.error("Unable to connect Amazon RDS:", error);
                ConfigureDatabase.sequelize = null;
            }
        }
    }
}

export function getSequelize() {
    if (!ConfigureDatabase.sequelize) {
        throw new Error("Sequelize instance is not created");
    }
    return ConfigureDatabase.sequelize;
}

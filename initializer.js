import { GlobalErrorHandler } from "./globalErrorHandler.js";
import { ConfigureDatabase } from "./dbconfig.js";
import { MessageQueue } from "./MessageQueue.js";
import { ConsumerMethodHandler } from "./ConsumerMethodHandler.js";

class Initializer {
    async init() {
        this.initiateGlobalErrorHandler();
        await this.initiateDatabase();
        await this.initiateDatabaseSync();
        await this.initiateMessageQueue();
        this.initiateConsumerMethodHandler();
    }

    initiateGlobalErrorHandler() {
        return new GlobalErrorHandler();
    }

    async initiateDatabase() {
        await new ConfigureDatabase().connectToAmazonRDS();
    }

    async initiateMessageQueue() {
        if (!MessageQueue.connection) {
            return await new MessageQueue().initiateMessageQueue();
        }
    }

    initiateConsumerMethodHandler() {
        new ConsumerMethodHandler().setEventsInConsumer();
    }

    async initiateDatabaseSync() {
        const userModule = await import("./Models/userModel.js");
        const User = userModule.default;

        User.sync({ alter: true })
            .then(() => {
                console.log("User table has been synched");
            })
            .catch((error) => {
                console.log(
                    `Error Occurred while synching with User table. \nError: ${error} `,
                );
            });
    }
}

export default Initializer;

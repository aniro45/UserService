export class GlobalErrorHandler {
    constructor() {
        this.handleUncaughtException();
        this.handleUnhandledRejection();
    }

    handleUncaughtException() {
        process.on("uncaughtException", function (err) {
            if (err.code === "ECONNRESET") {
                console.log("ECONNRESET was caught!");
            }
        });
    }

    handleUnhandledRejection() {
        process.on("unhandledRejection", (reason, promise) => {
            console.log("Unhandled Rejection at:", promise, "reason:", reason);
        });
    }
}

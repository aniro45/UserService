import dotenv from "dotenv";
dotenv.config();
import Initializer from "./initializer.js";

const initializer = new Initializer();
await initializer.init().catch((error) => {
    console.log("Error while initializing", error);
});

const appModule = await import("./app.js"); //async import
const app = appModule.default;

const port = process.env.PORT || 5560;
app.listen(port, (req, res) => {
    console.log(`User service is running on port ${port}`);
});

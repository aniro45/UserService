import dotenv from 'dotenv';
dotenv.config();

import { ConfigureDatabase } from './dbconfig.js';
await new ConfigureDatabase().connectToAmazonRDS();

const appModule = await import('./app.js');
const app = appModule.default;

const userModule = await import('./Models/userModel.js');
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

const port = process.env.PORT || 5560; 
app.listen(port, (req, res) => {
    console.log(`User service is running on port ${port}`);
});

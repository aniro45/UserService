import { connect } from "amqplib";

export class MessageQueue {
    static connection = null;

    async initiateMessageQueue() {
        try {
            const {
                RABBIT_MQ_HOST,
                RABBIT_MQ_PORT,
                RABBIT_MQ_USERNAME,
                RABBIT_MQ_PASSWORD,
            } = process.env;
            const url = `amqps://${RABBIT_MQ_USERNAME}:${RABBIT_MQ_PASSWORD}@${RABBIT_MQ_HOST}:${RABBIT_MQ_PORT}/`;
            MessageQueue.connection = await connect(url);
        } catch (error) {
            console.error(error);
        }
    }

    static publish = async (queue, message) => {
        try {
            if (!MessageQueue.connection) {
                console.log("connection not present");
                return;
            }
            const channel = await MessageQueue.connection.createChannel();

            await channel.assertQueue(queue, { durable: false });
            await channel.sendToQueue(queue, Buffer.from(message));

            console.log(`published message in ${queue} queue.`);
        } catch (error) {
            console.log("Error", error);
        }
    };

    static async consume(queue, callback) {
        if (!MessageQueue.connection) {
            console.log("connection does not exists!");
            return;
        }

        const channel = await MessageQueue.connection.createChannel();

        await channel.assertQueue(queue, { durable: false });

        channel.consume(
            queue,
            (msg) => {
                const stringifiedMessage = msg.content.toString();
                const parsedMessage = JSON.parse(stringifiedMessage);
                callback(parsedMessage);
            },
            { noAck: true },
        );
    }
}

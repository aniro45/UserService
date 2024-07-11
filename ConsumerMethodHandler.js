import { MessageQueue } from "./MessageQueue.js";
import { ConsumerQueueNames } from "./constants.js";

export class ConsumerMethodHandler {
    setEventsInConsumer() {
        const { TEST_SIGNAL } = ConsumerQueueNames;
        MessageQueue.consume(TEST_SIGNAL, () => {});
    }
}

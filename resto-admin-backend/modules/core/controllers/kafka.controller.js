const chalk = require('chalk');

exports.sendMessage = async function(topic, messages) {

  try {

    // Ensure the producer is connected
    if (!global.kafkaProducer) {
      throw {
        message: 'Kafka producer not initialized'
      }
    }

    // Send the message to the specified topic
    await global.kafkaProducer.send({
      topic: topic,
      messages: messages // e.g., [{ value: 'Hello KafkaJS!' }]
    });

    console.log('Message sent successfully to topic', topic, messages);
  } catch (error) {

    // TODO : What if kafka goes down?
    const date = new Date().toISOString(); // Converts to standard ISO format
    console.error(`${chalk.red(`${date}:Error sending message:${error}`)}`);
  }
};


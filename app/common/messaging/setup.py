import pika

from app.common.config import RabbitMQConfig
from app.common.messaging.event_keys import EventKeys


def setup():
    """Declare the configured exchange, inbox bindings, and dead letter topology.

    Returns:
        None: No return value.
    """
    cfg = RabbitMQConfig.from_env()
    connection = pika.BlockingConnection(pika.URLParameters(cfg.url))

    try:
        channel = connection.channel()

        # Shared event exchange
        channel.exchange_declare(exchange=cfg.exchange, exchange_type=cfg.exchange_type, durable=True)

        # Platform receives assessment events, including step completion.
        channel.queue_declare(queue="platform.inbox", durable=True)
        channel.queue_bind(
            exchange=cfg.exchange,
            queue="platform.inbox",
            routing_key="assessment.#"
        )

        # Dead Letter Exchange
        channel.exchange_declare(exchange=cfg.dlx, exchange_type="direct", durable=True)

        # Dead Letter Queue
        channel.queue_declare(queue=cfg.dlq, durable=True)
        channel.queue_bind(queue=cfg.dlq, exchange=cfg.dlx, routing_key=cfg.dlq)

        # Main Vulnerability Queue
        channel.queue_declare(
            queue=cfg.queue,
            durable=True,
            arguments={
                "x-dead-letter-exchange": cfg.dlx,
                "x-dead-letter-routing-key": cfg.dlq
            }
        )
        channel.queue_bind(exchange=cfg.exchange, queue=cfg.queue, routing_key=cfg.request_binding)
        channel.queue_bind(exchange=cfg.exchange, queue=cfg.queue, routing_key=cfg.cancel_binding)
        channel.queue_bind(queue=cfg.queue, exchange=cfg.exchange, routing_key=EventKeys.ASSESSMENT_REQUESTED)

        print("RabbitMQ topology initialized")

    finally:
        if connection.is_open:
            connection.close()


if __name__ == "__main__":
    setup()

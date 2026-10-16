"""Read-only preflight. Platform alone provisions exchanges, queues and bindings."""

import pika

from app.common.config import RabbitMQConfig
from app.common.messaging.rabbitmq import check_topology


def setup():
    cfg = RabbitMQConfig.from_env()
    connection = pika.BlockingConnection(pika.URLParameters(cfg.url))
    try:
        check_topology(connection.channel(), cfg)
        print(f"Platform messaging topology v{cfg.topology_version}: exchange and inbox exist")
    except pika.exceptions.ChannelClosedByBroker as exc:
        raise RuntimeError(
            f"RabbitMQ preflight failed ({exc.reply_code}): {exc.reply_text}. "
            "Check broker/vhost and run Platform messaging bootstrap. No topology was changed."
        ) from exc
    finally:
        if connection.is_open:
            connection.close()


if __name__ == "__main__":
    setup()

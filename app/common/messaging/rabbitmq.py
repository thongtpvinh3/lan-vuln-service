import json
import logging
import time

from concurrent.futures import ThreadPoolExecutor

import pika
import pika.exceptions

from app.common.config import RabbitMQConfig
from app.common.messaging.event import BaseEvent

logger = logging.getLogger(__name__)


def check_topology(channel, config: RabbitMQConfig):
    """Check existence only; passive AMQP declarations do not validate arguments/bindings."""
    channel.exchange_declare(exchange=config.exchange, passive=True)
    channel.queue_declare(queue=config.queue, passive=True)


def is_retryable_broker_error(exc):
    # Missing topology may be provisioned by Platform after this worker starts.
    # Permission errors and incompatible settings need operator intervention.
    if isinstance(exc, pika.exceptions.ConnectionClosedByBroker):
        return exc.reply_code not in {403, 406, 530}
    return exc.reply_code == 404


class RabbitEventBus:

    def __init__(self, config: RabbitMQConfig):
        self.config = config
        self.handlers = {}

    def _connect(self):
        params = pika.URLParameters(self.config.url)
        params.heartbeat = 60
        params.blocked_connection_timeout = 30
        params.socket_timeout = 15

        return pika.BlockingConnection(params)

    def publish(self, routing_key: str, event: BaseEvent):
        """
        Mở kết nối riêng, publish có confirm, sau đó đóng kết nối.
        Không tự retry khi trạng thái xác nhận chưa rõ để tránh tạo event_id mới.
        """
        connection = self._connect()

        try:
            channel = connection.channel()
            channel.exchange_declare(exchange=self.config.exchange, passive=True)
            channel.confirm_delivery()
            body = json.dumps(event.to_dict(), ensure_ascii=False).encode("utf-8")

            channel.basic_publish(
                exchange=self.config.exchange,
                routing_key=routing_key,
                body=body,
                mandatory=True,
                properties=pika.BasicProperties(
                    content_type="application/json",
                    content_encoding="utf-8",
                    delivery_mode=2,
                    message_id=event.message_id,
                    correlation_id=event.data.get("stage_run_id")
                )
            )

            logger.info("Published event=%s message_id=%s", routing_key, event.message_id)

        finally:
            if connection.is_open: connection.close()

    def subscribe(self, event_type: str, handler):
        if event_type not in self.config.list_event_type:
            raise ValueError(f"Unsupported event type: {event_type}")
        if event_type in self.handlers:
            raise ValueError(f"Handler already registered: {event_type}")
        self.handlers[event_type] = handler
        logger.info("Registered handler for event=%s", event_type)

    def _dispatch(self, routing_key: str, body: bytes):
        event = json.loads(body)

        if not isinstance(event, dict):
            raise ValueError("Event must be a JSON object")

        if event.get("event") != routing_key:
            raise ValueError("Event name and routing key do not match")

        handler = self.handlers.get(routing_key)

        if handler is None:
            raise ValueError(f"No handler for {routing_key}")

        handler(event)

    def start(self):
        """
        Consumer kết nối lâu dài.
        Handler chạy trong executor riêng. ACK/NACK được đưa về RabbitMQ I/O thread.
        """
        if not self.handlers: raise RuntimeError("No event handlers registered")

        with ThreadPoolExecutor(max_workers=1) as executor:
            while True:
                connection = None

                try:
                    connection = self._connect()
                    channel = connection.channel()
                    check_topology(channel, self.config)
                    channel.basic_qos(prefetch_count=1)

                    def on_message(ch, method, properties, body):
                        tag = method.delivery_tag
                        routing_key = method.routing_key

                        # Giữ reference tới connection hiện tại.
                        conn = connection
                        logger.info("Received event=%s delivery_tag=%s", routing_key, tag)

                        future = executor.submit(self._dispatch, method.routing_key, body)

                        def on_done(result, consumer_conn=conn, consumer_ch=ch, delivery_tag=tag):
                            def settle():
                                if not consumer_conn.is_open or not consumer_ch.is_open:
                                    logger.warning("Connection closed before settlement")
                                    return
                                try:
                                    result.result()
                                except Exception:
                                    logger.exception("Event handling failed")
                                    consumer_ch.basic_nack(delivery_tag=tag, requeue=False)
                                else:
                                    consumer_ch.basic_ack(delivery_tag=tag)
                                    logger.info("Event acknowledged tag=%s", delivery_tag)

                            try:
                                consumer_conn.add_callback_threadsafe(settle)
                            except pika.exceptions.AMQPError:
                                logger.exception("Cannot schedule ACK/NACK")

                        future.add_done_callback(on_done)

                    channel.basic_consume(queue=self.config.queue, on_message_callback=on_message, auto_ack=False)
                    logger.info("RabbitMQ listening on queue=%s", self.config.queue)
                    channel.start_consuming()
                except KeyboardInterrupt:
                    logger.info("RabbitMQ consumer stopped")
                    break
                except (pika.exceptions.ChannelClosedByBroker, pika.exceptions.ConnectionClosedByBroker) as exc:
                    if not is_retryable_broker_error(exc):
                        logger.error("RabbitMQ refused consumer (%s): %s; check configuration and permissions",
                                     exc.reply_code, exc.reply_text)
                        raise
                    if exc.reply_code == 404:
                        logger.warning("Platform topology is not ready; waiting for bootstrap")
                    else:
                        logger.warning("RabbitMQ connection closed by broker (%s); reconnecting", exc.reply_code)
                    time.sleep(5)
                except (pika.exceptions.ProbableAuthenticationError, pika.exceptions.ProbableAccessDeniedError):
                    logger.exception("RabbitMQ authentication/vhost access failed; check credentials and permissions")
                    raise
                except (pika.exceptions.AMQPError, OSError):
                    logger.exception("RabbitMQ disconnected; reconnecting")
                    time.sleep(5)

                finally:
                    if connection and connection.is_open: connection.close()

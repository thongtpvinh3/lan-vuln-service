import json
import logging
import time
from threading import Thread

from concurrent.futures import Future

import pika
import pika.exceptions

from app.common.config import RabbitMQConfig
from app.common.messaging.event import BaseEvent

logger = logging.getLogger(__name__)


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
        Mỗi message chạy trong thread riêng. ACK/NACK được đưa về RabbitMQ I/O thread.
        """
        if not self.handlers: raise RuntimeError("No event handlers registered")

        workers = []
        try:
            while True:
                connection = None

                try:
                    connection = self._connect()
                    channel = connection.channel()
                    channel.exchange_declare(exchange=self.config.exchange, passive=True)
                    channel.queue_declare(queue=self.config.queue, passive=True)
                    self._bind_queues(channel)
                    # Allow new messages while earlier assessments are still running.
                    channel.basic_qos(prefetch_count=0)

                    def on_message(ch, method, properties, body):
                        tag = method.delivery_tag
                        routing_key = method.routing_key

                        # Giữ reference tới connection hiện tại.
                        conn = connection
                        logger.info("Received event=%s delivery_tag=%s", routing_key, tag)

                        future = Future()

                        def on_done(result, consumer_conn=conn, consumer_ch=ch, delivery_tag=tag):
                            def settle():
                                if not consumer_conn.is_open or not consumer_ch.is_open:
                                    logger.warning("Connection closed before settlement")
                                    return
                                try:
                                    result.result()
                                except Exception:
                                    logger.exception("Event handling failed")
                                    consumer_ch.basic_nack(delivery_tag=delivery_tag, requeue=False)
                                else:
                                    consumer_ch.basic_ack(delivery_tag=delivery_tag)
                                    logger.info("Event acknowledged tag=%s", delivery_tag)

                            try:
                                consumer_conn.add_callback_threadsafe(settle)
                            except pika.exceptions.AMQPError:
                                logger.exception("Cannot schedule ACK/NACK")

                        future.add_done_callback(on_done)

                        def process_message(result=future, key=routing_key, payload=body):
                            try:
                                self._dispatch(key, payload)
                            except BaseException as error:
                                result.set_exception(error)
                            else:
                                result.set_result(None)

                        workers[:] = [worker for worker in workers if worker.is_alive()]
                        worker = Thread(
                            target=process_message,
                            name=f"assessment-message-{tag}",
                            daemon=False,
                        )
                        worker.start()
                        workers.append(worker)

                    channel.basic_consume(queue=self.config.queue, on_message_callback=on_message, auto_ack=False)
                    logger.info("RabbitMQ listening on queue=%s", self.config.queue)
                    channel.start_consuming()
                except KeyboardInterrupt:
                    logger.info("RabbitMQ consumer stopped")
                    break
                except (pika.exceptions.AMQPError, OSError):
                    logger.exception("RabbitMQ disconnected; reconnecting")
                    time.sleep(5)

                finally:
                    if connection and connection.is_open: connection.close()
        finally:
            for worker in workers:
                worker.join()

    def _bind_queues(self, channel):
        """
        Bind queue theo RabbitMQConfig. Không bind theo self.handlers.
        """
        channel.queue_bind(
            queue=self.config.queue,
            exchange=self.config.exchange,
            routing_key=self.config.request_binding
        )

        channel.queue_bind(
            queue=self.config.queue,
            exchange=self.config.exchange,
            routing_key=self.config.cancel_binding
        )

        logger.info(
            "Queue bindings configured: queue=%s bindings=%s,%s",
            self.config.queue,
            self.config.request_binding,
            self.config.cancel_binding
        )

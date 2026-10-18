import json
import logging
import time

from concurrent.futures import ThreadPoolExecutor

import pika
import pika.exceptions

from app.common.config import RabbitMQConfig
from app.common.messaging.event import BaseEvent

logger = logging.getLogger(__name__)


class RabbitEventBus:

    def __init__(self, config: RabbitMQConfig):
        """Store broker configuration and initialize an empty handler registry.

        Args:
            config (RabbitMQConfig): Broker URL, exchange, queue, bindings, and allowed
                event types.

        Returns:
            None: No return value.
        """
        self.config = config
        self.handlers = {}

    def _connect(self):
        """Open a broker connection with heartbeat and socket timeouts.

        Returns:
            pika.BlockingConnection: New connection owned by the caller.
        """
        params = pika.URLParameters(self.config.url)
        params.heartbeat = 60
        params.blocked_connection_timeout = 30
        params.socket_timeout = 15

        return pika.BlockingConnection(params)

    def publish(self, routing_key: str, event: BaseEvent):
        """Publish a persistent event with delivery confirmation and close its connection.

        Uncertain confirmations are not automatically retried.

        Args:
            routing_key (str): Topic routing key used to publish the event.
            event (BaseEvent): Event envelope to serialize as UTF-8 JSON.

        Returns:
            None: No return value.
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
        """Register one handler for an allowed event type; reject duplicates.

        Args:
            event_type (str): Event name listed in the configured allowed event types.
            handler (Callable[[dict], None]): Callback invoked with the decoded event
                envelope.

        Returns:
            None: No return value.
        """
        if event_type not in self.config.list_event_type:
            raise ValueError(f"Unsupported event type: {event_type}")
        if event_type in self.handlers:
            raise ValueError(f"Handler already registered: {event_type}")
        self.handlers[event_type] = handler
        logger.info("Registered handler for event=%s", event_type)

    def _dispatch(self, routing_key: str, body: bytes):
        """Validate the decoded event and invoke its registered handler.

        Args:
            routing_key (str): Received routing key, which must equal the envelope event
                name.
            body (bytes): UTF-8 JSON event body.

        Returns:
            None: No return value.
        """
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
        """Consume events with one worker and settle deliveries on the broker I/O thread.

        Reconnect after broker or socket errors. Failed handlers are NACKed without
        requeue; KeyboardInterrupt stops the consumer loop.

        Returns:
            None: Returns after the consumer is interrupted.
        """
        if not self.handlers: raise RuntimeError("No event handlers registered")

        with ThreadPoolExecutor(max_workers=1) as executor:
            while True:
                connection = None

                try:
                    connection = self._connect()
                    channel = connection.channel()
                    channel.exchange_declare(exchange=self.config.exchange, passive=True)
                    channel.queue_declare(queue=self.config.queue, passive=True)
                    self._bind_queues(channel)
                    channel.basic_qos(prefetch_count=1)

                    def on_message(ch, method, properties, body):
                        """Submit a delivery to the worker and register its settlement
                        callback.

                        Args:
                            ch (pika.adapters.blocking_connection.BlockingChannel): Channel
                                receiving the delivery.
                            method (pika.spec.Basic.Deliver): Delivery metadata containing
                                routing key and delivery tag.
                            properties (pika.BasicProperties): Message properties supplied
                                by Pika; unused here.
                            body (bytes): Serialized JSON event body.

                        Returns:
                            None: No return value.
                        """
                        tag = method.delivery_tag
                        routing_key = method.routing_key

                        # Giữ reference tới connection hiện tại.
                        conn = connection
                        logger.info("Received event=%s delivery_tag=%s", routing_key, tag)

                        future = executor.submit(self._dispatch, method.routing_key, body)

                        def on_done(result, consumer_conn=conn, consumer_ch=ch, delivery_tag=tag):
                            """Schedule delivery settlement on the original connection I/O thread.

                            Args:
                                result (concurrent.futures.Future[None]): Completed event
                                    handler task.
                                consumer_conn (pika.BlockingConnection): Connection captured
                                    when the delivery was received.
                                consumer_ch (pika.adapters.blocking_connection.BlockingChannel):
                                    Original delivery channel.
                                delivery_tag (int): Captured delivery tag parameter; settlement
                                    uses the enclosing tag.

                            Returns:
                                None: No return value.
                            """
                            def settle():
                                """ACK a successful task or NACK a failed task if its connection
                                remains open.

                                Returns:
                                    None: No return value.
                                """
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
                except (pika.exceptions.AMQPError, OSError):
                    logger.exception("RabbitMQ disconnected; reconnecting")
                    time.sleep(5)

                finally:
                    if connection and connection.is_open: connection.close()

    def _bind_queues(self, channel):
        """Bind the inbox using configured request and cancellation routing patterns.

        Args:
            channel (pika.adapters.blocking_connection.BlockingChannel): Open channel
                used to create bindings.

        Returns:
            None: No return value.
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

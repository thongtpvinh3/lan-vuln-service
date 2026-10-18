from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from app.common.config import DatabaseConfig


# SQLAlchemy Engine tự quản lý connection pool. create_engine() chưa lập tức mở toàn bộ các kết nối PostgreSQL
# kết nối được tạo khi ứng dụng thực sự cần sử dụng
class Postgres:

    def __init__(self, config: DatabaseConfig):
        """Create a SQLAlchemy engine with a lazily opened PostgreSQL connection pool.

        Args:
            config (DatabaseConfig): Database URL, pool limits, connection timeout, and
                SQL logging settings.

        Returns:
            None: No return value.
        """
        self.engine: Engine = create_engine(
            url=config.url,
            pool_size=config.pool_size,
            max_overflow=config.max_overflow,
            pool_timeout=config.pool_timeout,
            pool_recycle=config.pool_recycle,
            pool_pre_ping=True,
            connect_args={"connect_timeout": config.connect_timeout},
            echo=config.echo,
            hide_parameters=True
        )

    def connect(self):
        """Acquire a connection for queries; callers should close it or use a with block.

        Returns:
            sqlalchemy.engine.Connection: Open connection checked out from the pool.
        """
        return self.engine.connect()

    def transaction(self):
        """Create a transaction context that commits on success and rolls back on error.

        Returns:
            contextlib.AbstractContextManager[sqlalchemy.engine.Connection]: Context
                yielding a transactional connection.
        """
        return self.engine.begin()

    def ping(self) -> bool:
        """Execute SELECT 1 to check connectivity; connection errors propagate.

        Returns:
            bool: True when the database returns 1.
        """
        with self.connect() as conn:
            return conn.execute(text("SELECT 1")).scalar_one() == 1

    def close(self):
        """Dispose idle connections managed by the engine.

        Returns:
            None: No return value.
        """
        self.engine.dispose()

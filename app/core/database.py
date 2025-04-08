from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker, declarative_base

from app.configs.configs import settings
from app.db.base_class import Base
from app.utils.logs import get_logger
logger = get_logger(__name__)


engine = create_engine(settings.DB_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    """
    Dependency that provides a database session for FastAPI routes.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_db_n_tables():
    """
    Create the database and tables if they do not exist.
    """
    inspector = inspect(engine)
    existing_tables = inspector.get_table_names()
    logger.warning(f"existing tables: {existing_tables}")

    all_model_tables = Base.metadata.tables.keys()
    logger.warning(f"all model tables: {all_model_tables}")
    missing_tables = [t for t in all_model_tables if t not in existing_tables]
    logger.warning(f"missing tables: {missing_tables}")

    if missing_tables:
        logger.info(f"Creating missing tables: {missing_tables}")
        Base.metadata.create_all(bind=engine)
    else:
        logger.info("All tables already exist. No action taken.")


def check_db_connection():
    """
    Check the database connection.
    """
    try:
        conn = get_db()
        conn.send(None)  # Trigger the generator to establish a connection
        conn.close()  # Close the connection
        logger.info("Database connection successful.")
        return True
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        raise
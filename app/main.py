from contextlib import asynccontextmanager
from fastapi import FastAPI

from app.core.database import check_db_connection, create_db_n_tables
from app.core.redis import check_redis_connection
from app.middlewares.request_logger import RequestLoggingMiddleware
from app.utils.logs import get_logger
from app.api import auth, users
from app.configs.configs import settings

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting up...")
    # create necessary tables
    logger.info("Connecting to database...")
    check_db_connection()
    if settings.REDIS_ENABLED:
        logger.info("Connecting to redis...")
        check_redis_connection()

    # create database and tables
    logger.info("Creating database and tables...")
    create_db_n_tables()
    logger.info("Database and tables created.")
    # Perform any startup tasks here
    logger.info("Application's ready...")
    yield
    print("Shutting down...")


app = FastAPI(title="Authentication micro-service", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    RequestLoggingMiddleware
)

@app.get("/")
async def root():
    return {"message": "Welcome to Authentication API"}
@app.get("/health")
async def health():
    return {"status": "healthy"}
@app.get("/status")
async def status():
    return {"status": "running"}


app.include_router(
    auth.router, 
    prefix="/auth", 
    tags=["Authentication"]
    # dependencies=[Depends(get_db)],  # Uncomment if you want to use the dependency for all routes, since we're checking the DB connection on startup, no need to add here
    # include_in_schema=False,  # Uncomment if you want to exclude this router from the OpenAPI schema
    # default_response_class=JSONResponse,  # Uncomment if you want to set a default response class
)
app.include_router(users.router, prefix="/users", tags=["Users"])

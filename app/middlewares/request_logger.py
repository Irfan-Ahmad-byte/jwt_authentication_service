from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request
from app.utils.logs import get_logger

logger = get_logger(__name__)

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        ip = request.client.host
        path = request.url.path
        method = request.method
        logger.info(f"📥 Request from {ip} - {method} {path}")
        response = await call_next(request)
        return response

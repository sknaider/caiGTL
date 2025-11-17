"""
API Routes Package

Modular route definitions for GTL API Gateway.
"""

from gtl_api_gateway.routes.scanner import router as scanner_router

__all__ = ["scanner_router"]

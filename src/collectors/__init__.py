"""
Collectors Module - Coletores de evidências por plataforma
"""

from .base import (
    BaseCollector,
    CollectionConfig,
    CollectionResult,
    AuthenticationError,
    CollectionError
)

# Importações condicionais
try:
    from .docker_collector import DockerCollector
except ImportError:
    DockerCollector = None

__all__ = [
    'BaseCollector',
    'CollectionConfig',
    'CollectionResult',
    'AuthenticationError',
    'CollectionError',
    'DockerCollector'
]

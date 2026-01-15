
from .base import (
    BaseCollector,
    CollectionConfig,
    CollectionResult,
    AuthenticationError,
    CollectionError
)

# Importações condicionais - não falham se SDK não estiver instalado

# AWS Collector
try:
    from .aws_collector import AWSCollector
except ImportError:
    AWSCollector = None

# Azure Collector
try:
    from .azure_collector import AzureCollector
except ImportError:
    AzureCollector = None

# GCP Collector
try:
    from .gcp_collector import GCPCollector
except ImportError:
    GCPCollector = None

# Docker Collector
try:
    from .docker_collector import DockerCollector
except ImportError:
    DockerCollector = None

# Kubernetes Collector (futuro)
try:
    from .k8s_collector import KubernetesCollector
except ImportError:
    KubernetesCollector = None


def get_available_collectors() -> dict:
    """
    Retorna um dicionário com os coletores disponíveis.

    Returns:
        dict: Mapeamento de nome -> classe do coletor (ou None se indisponível)
    """
    return {
        'aws': AWSCollector,
        'azure': AzureCollector,
        'gcp': GCPCollector,
        'docker': DockerCollector,
        'kubernetes': KubernetesCollector
    }


def check_collector_availability() -> dict:
    """
    Verifica quais coletores estão disponíveis.

    Returns:
        dict: Mapeamento de nome -> bool (True se disponível)
    """
    collectors = get_available_collectors()
    return {name: cls is not None for name, cls in collectors.items()}


__all__ = [
    # Classes base
    'BaseCollector',
    'CollectionConfig',
    'CollectionResult',
    'AuthenticationError',
    'CollectionError',

    # Coletores
    'AWSCollector',
    'AzureCollector',
    'GCPCollector',
    'DockerCollector',
    'KubernetesCollector',

    # Utilitários
    'get_available_collectors',
    'check_collector_availability'
]

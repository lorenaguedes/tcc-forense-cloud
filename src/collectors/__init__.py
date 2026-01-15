"""
Collectors Module - Coletores de evidências por plataforma
==========================================================

Este módulo fornece coletores para extrair evidências forenses
de diferentes provedores de nuvem e ambientes de containers.

Coletores disponíveis:
- AWSCollector: Amazon Web Services (CloudTrail, CloudWatch, S3, EC2)
- AzureCollector: Microsoft Azure (Activity Log, Blob Storage, VMs)
- GCPCollector: Google Cloud Platform (Cloud Logging, GCS, Compute)
- DockerCollector: Docker containers e imagens
- KubernetesCollector: Kubernetes pods, eventos e recursos (futuro)

Uso básico:
    >>> from src.collectors import CollectionConfig, DockerCollector
    >>> 
    >>> config = CollectionConfig(
    ...     case_id="CASO-2025-001",
    ...     agent_name="Perito Silva",
    ...     agent_id="PER001",
    ...     output_dir="./output"
    ... )
    >>> 
    >>> collector = DockerCollector(config)
    >>> result = collector.collect("all_containers")
    >>> print(f"Coletadas {result.evidence_count} evidências")

Autor: [Seu Nome]
"""

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

# Kubernetes Collector
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

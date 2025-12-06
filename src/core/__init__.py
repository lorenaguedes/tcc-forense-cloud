"""
Core Module - Funcionalidades centrais do framework forense
"""

from .hasher import (
    ForensicHasher,
    HashResult,
    calculate_sha256,
    verify_sha256
)

from .manifest import (
    ManifestGenerator,
    ForensicManifest,
    EvidenceItem,
    AgentInfo,
    SourceInfo,
    ChainOfCustodyEntry,
    create_manifest
)

__all__ = [
    # Hasher
    'ForensicHasher',
    'HashResult',
    'calculate_sha256',
    'verify_sha256',
    # Manifest
    'ManifestGenerator',
    'ForensicManifest',
    'EvidenceItem',
    'AgentInfo',
    'SourceInfo',
    'ChainOfCustodyEntry',
    'create_manifest'
]

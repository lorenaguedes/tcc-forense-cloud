"""
Módulo de Manifesto Forense
===========================

Gera manifestos JSON documentando a coleta de evidências,
incluindo hashes, metadados e cadeia de custódia.

O manifesto é preparado para registro em blockchain (Fase 4).

Autor: [Seu Nome]
"""

import json
import os
import platform
import socket
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import structlog

from .hasher import ForensicHasher

logger = structlog.get_logger(__name__)

MANIFEST_SCHEMA_VERSION = "1.0.0"


@dataclass
class AgentInfo:
    """Informações do agente/perito que realizou a coleta."""
    
    name: str
    agent_id: str
    hostname: str = field(default_factory=socket.gethostname)
    username: str = field(default_factory=lambda: os.getenv('USERNAME', os.getenv('USER', 'unknown')))
    ip_address: str = ""
    os_info: str = field(default_factory=lambda: f"{platform.system()} {platform.release()}")
    
    def __post_init__(self):
        if not self.ip_address:
            try:
                self.ip_address = socket.gethostbyname(socket.gethostname())
            except socket.gaierror:
                self.ip_address = "127.0.0.1"


@dataclass
class SourceInfo:
    """Informações sobre a fonte das evidências."""
    
    source_type: str
    provider: str
    region: str = ""
    account_id: str = ""
    resource_id: str = ""
    additional_info: dict = field(default_factory=dict)


@dataclass
class EvidenceItem:
    """Item individual de evidência coletada."""
    
    filename: str
    original_path: str
    local_path: str
    size_bytes: int
    sha256: str
    sha512: str = ""
    mime_type: str = "application/octet-stream"
    collected_at: str = ""
    metadata: dict = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.collected_at:
            self.collected_at = datetime.now(timezone.utc).isoformat()


@dataclass
class ChainOfCustodyEntry:
    """Entrada na cadeia de custódia."""
    
    action: str
    timestamp: str
    agent_id: str
    description: str
    hash_before: str = ""
    hash_after: str = ""


@dataclass
class ForensicManifest:
    """Manifesto forense completo de uma coleta."""
    
    collection_id: str
    case_id: str
    agent: AgentInfo
    source: SourceInfo
    schema_version: str = MANIFEST_SCHEMA_VERSION
    created_at: str = ""
    evidence_items: list = field(default_factory=list)
    chain_of_custody: list = field(default_factory=list)
    notes: str = ""
    ready_for_blockchain: bool = False
    manifest_hash: str = ""
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()
        if not self.collection_id:
            self.collection_id = str(uuid.uuid4())


class ManifestGenerator:
    """
    Gerador e gerenciador de manifestos forenses.
    
    Example:
        >>> generator = ManifestGenerator(
        ...     case_id="CASO-2025-001",
        ...     agent_name="Perito Silva",
        ...     agent_id="PER001"
        ... )
        >>> generator.set_source("docker_logs", "docker")
        >>> generator.add_evidence_file("./evidencia.log")
        >>> generator.save("./output/manifest.json")
    """
    
    def __init__(
        self,
        case_id: str,
        agent_name: str,
        agent_id: str,
        collection_id: Optional[str] = None
    ):
        self.hasher = ForensicHasher(algorithm='sha256')
        self.hasher_512 = ForensicHasher(algorithm='sha512')
        
        agent = AgentInfo(name=agent_name, agent_id=agent_id)
        source = SourceInfo(source_type="undefined", provider="undefined")
        
        self.manifest = ForensicManifest(
            collection_id=collection_id or str(uuid.uuid4()),
            case_id=case_id,
            agent=agent,
            source=source
        )
        
        self._add_custody_entry(
            action="COLLECTION_STARTED",
            description=f"Início da coleta para o caso {case_id}"
        )
        
        logger.info(
            "ManifestGenerator inicializado",
            collection_id=self.manifest.collection_id,
            case_id=case_id
        )
    
    def set_source(
        self,
        source_type: str,
        provider: str,
        region: str = "",
        account_id: str = "",
        resource_id: str = "",
        **additional_info
    ) -> None:
        """Define as informações da fonte das evidências."""
        self.manifest.source = SourceInfo(
            source_type=source_type,
            provider=provider,
            region=region,
            account_id=account_id,
            resource_id=resource_id,
            additional_info=additional_info
        )
        logger.info("Fonte configurada", source_type=source_type)
    
    def add_evidence_file(
        self,
        file_path: str,
        original_path: str = "",
        mime_type: str = "",
        metadata: Optional[dict] = None
    ) -> EvidenceItem:
        """Adiciona um arquivo de evidência ao manifesto."""
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"Arquivo não encontrado: {file_path}")
        
        hash_256 = self.hasher.hash_file(file_path)
        hash_512 = self.hasher_512.hash_file(file_path)
        
        if not mime_type:
            mime_type = self._detect_mime_type(file_path)
        
        evidence = EvidenceItem(
            filename=file_path.name,
            original_path=original_path or str(file_path),
            local_path=str(file_path.absolute()),
            size_bytes=hash_256.file_size,
            sha256=hash_256.hash_value,
            sha512=hash_512.hash_value,
            mime_type=mime_type,
            metadata=metadata or {}
        )
        
        self.manifest.evidence_items.append(evidence)
        
        self._add_custody_entry(
            action="EVIDENCE_COLLECTED",
            description=f"Evidência coletada: {evidence.filename}",
            hash_after=evidence.sha256
        )
        
        logger.info("Evidência adicionada", filename=evidence.filename)
        return evidence
    
    def add_evidence_bytes(
        self,
        data: bytes,
        filename: str,
        original_path: str = "",
        mime_type: str = "application/octet-stream",
        metadata: Optional[dict] = None
    ) -> EvidenceItem:
        """Adiciona dados em memória como evidência."""
        sha256 = self.hasher.hash_bytes(data)
        sha512 = self.hasher_512.hash_bytes(data)
        
        evidence = EvidenceItem(
            filename=filename,
            original_path=original_path,
            local_path="[in-memory]",
            size_bytes=len(data),
            sha256=sha256,
            sha512=sha512,
            mime_type=mime_type,
            metadata=metadata or {}
        )
        
        self.manifest.evidence_items.append(evidence)
        
        self._add_custody_entry(
            action="EVIDENCE_COLLECTED",
            description=f"Evidência em memória: {filename}",
            hash_after=sha256
        )
        
        return evidence
    
    def add_note(self, note: str) -> None:
        """Adiciona observação ao manifesto."""
        timestamp = datetime.now(timezone.utc).isoformat()
        if self.manifest.notes:
            self.manifest.notes += f"\n[{timestamp}] {note}"
        else:
            self.manifest.notes = f"[{timestamp}] {note}"
    
    def _add_custody_entry(
        self,
        action: str,
        description: str,
        hash_before: str = "",
        hash_after: str = ""
    ) -> None:
        entry = ChainOfCustodyEntry(
            action=action,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=self.manifest.agent.agent_id,
            description=description,
            hash_before=hash_before,
            hash_after=hash_after
        )
        self.manifest.chain_of_custody.append(entry)
    
    def _detect_mime_type(self, file_path: Path) -> str:
        mime_map = {
            '.json': 'application/json',
            '.log': 'text/plain',
            '.txt': 'text/plain',
            '.xml': 'application/xml',
            '.csv': 'text/csv',
            '.gz': 'application/gzip',
            '.zip': 'application/zip',
        }
        return mime_map.get(file_path.suffix.lower(), 'application/octet-stream')
    
    def finalize(self) -> ForensicManifest:
        """Finaliza o manifesto e calcula seu hash."""
        self._add_custody_entry(
            action="COLLECTION_COMPLETED",
            description="Coleta finalizada"
        )
        
        self.manifest.ready_for_blockchain = True
        
        manifest_dict = self.to_dict()
        manifest_dict.pop('manifest_hash', None)
        manifest_json = json.dumps(manifest_dict, sort_keys=True)
        self.manifest.manifest_hash = self.hasher.hash_bytes(manifest_json.encode())
        
        logger.info("Manifesto finalizado", manifest_hash=self.manifest.manifest_hash[:16])
        return self.manifest
    
    def to_dict(self) -> dict:
        """Converte o manifesto para dicionário."""
        def convert(obj):
            if hasattr(obj, '__dataclass_fields__'):
                return {k: convert(v) for k, v in asdict(obj).items()}
            elif isinstance(obj, list):
                return [convert(item) for item in obj]
            return obj
        return convert(self.manifest)
    
    def to_json(self, indent: int = 2) -> str:
        """Converte o manifesto para JSON formatado."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
    
    def save(self, output_path: str) -> str:
        """Salva o manifesto em arquivo JSON."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        if not self.manifest.ready_for_blockchain:
            self.finalize()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(self.to_json())
        
        logger.info("Manifesto salvo", path=str(output_path))
        return str(output_path.absolute())
    
    @classmethod
    def load(cls, manifest_path: str) -> 'ManifestGenerator':
        """Carrega um manifesto existente."""
        with open(manifest_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        agent = AgentInfo(**data['agent'])
        source = SourceInfo(**data['source'])
        evidence_items = [EvidenceItem(**item) for item in data.get('evidence_items', [])]
        custody_entries = [ChainOfCustodyEntry(**entry) for entry in data.get('chain_of_custody', [])]
        
        generator = cls.__new__(cls)
        generator.hasher = ForensicHasher(algorithm='sha256')
        generator.hasher_512 = ForensicHasher(algorithm='sha512')
        
        generator.manifest = ForensicManifest(
            collection_id=data['collection_id'],
            case_id=data['case_id'],
            agent=agent,
            source=source,
            schema_version=data.get('schema_version', MANIFEST_SCHEMA_VERSION),
            created_at=data.get('created_at', ''),
            evidence_items=evidence_items,
            chain_of_custody=custody_entries,
            notes=data.get('notes', ''),
            ready_for_blockchain=data.get('ready_for_blockchain', False),
            manifest_hash=data.get('manifest_hash', '')
        )
        
        return generator


def create_manifest(
    case_id: str,
    agent_name: str,
    agent_id: str,
    source_type: str,
    provider: str,
    **source_kwargs
) -> ManifestGenerator:
    """Função de conveniência para criar manifesto."""
    generator = ManifestGenerator(case_id=case_id, agent_name=agent_name, agent_id=agent_id)
    generator.set_source(source_type, provider, **source_kwargs)
    return generator

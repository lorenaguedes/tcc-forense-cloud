"""
Classe Base para Coletores de Evidências
========================================

"""

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import structlog

from ..core.manifest import ManifestGenerator

logger = structlog.get_logger(__name__)


@dataclass
class CollectionConfig:
    """Configuração para uma operação de coleta."""

    case_id: str
    agent_name: str
    agent_id: str
    output_dir: str = "./output"
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    dry_run: bool = False
    max_size_mb: int = 1024
    extra_options: dict = field(default_factory=dict)

    def __post_init__(self):
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        if self.end_time is None:
            self.end_time = datetime.now(timezone.utc)


@dataclass
class CollectionResult:
    """Resultado de uma operação de coleta."""

    success: bool
    collection_id: str
    manifest_path: str = ""
    evidence_count: int = 0
    total_size_bytes: int = 0
    duration_seconds: float = 0.0
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)


class BaseCollector(ABC):
    """
    Classe base abstrata para coletores de evidências.

    Todos os coletores (AWS, Azure, Docker, etc.) devem herdar desta classe.
    """

    def __init__(self, config: CollectionConfig):
        self.config = config
        self.manifest_generator: Optional[ManifestGenerator] = None
        self._authenticated = False
        self._start_time: Optional[datetime] = None

        logger.info(
            f"Coletor {self.provider_name} inicializado",
            case_id=config.case_id
        )

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Nome do provedor (ex: 'aws', 'docker')."""
        pass

    @property
    @abstractmethod
    def supported_sources(self) -> list[str]:
        """Lista de fontes suportadas pelo coletor."""
        pass

    @abstractmethod
    def _authenticate(self) -> bool:
        """Autentica com o provedor."""
        pass

    @abstractmethod
    def _collect_source(self, source_type: str, **kwargs) -> list[str]:
        """Coleta evidências de uma fonte específica."""
        pass

    @abstractmethod
    def _get_source_metadata(self, source_type: str) -> dict:
        """Obtém metadados da fonte."""
        pass

    def authenticate(self) -> bool:
        """Wrapper público para autenticação."""
        logger.info(f"Autenticando com {self.provider_name}...")
        self._authenticated = self._authenticate()
        return self._authenticated

    def collect(self, source_type: str, **kwargs) -> CollectionResult:
        """Executa a coleta de evidências."""
        self._start_time = datetime.now(timezone.utc)
        result = CollectionResult(success=False, collection_id="")

        try:
            if source_type not in self.supported_sources:
                raise ValueError(
                    f"Fonte '{source_type}' não suportada. "
                    f"Disponíveis: {self.supported_sources}"
                )

            if not self._authenticated:
                self.authenticate()

            self._init_manifest(source_type, **kwargs)
            result.collection_id = self.manifest_generator.manifest.collection_id

            logger.info(f"Coletando {source_type}", dry_run=self.config.dry_run)

            if self.config.dry_run:
                logger.info("Modo dry-run: simulando coleta")
                collected_files = []
            else:
                collected_files = self._collect_source(source_type, **kwargs)

            for file_path in collected_files:
                try:
                    evidence = self.manifest_generator.add_evidence_file(
                        file_path=file_path,
                        original_path=self._get_original_path(file_path, source_type),
                        metadata=self._get_file_metadata(file_path)
                    )
                    result.total_size_bytes += evidence.size_bytes
                except Exception as e:
                    result.warnings.append(f"Erro ao processar {file_path}: {e}")

            result.evidence_count = len(self.manifest_generator.manifest.evidence_items)

            manifest_path = self._save_manifest(source_type)
            result.manifest_path = manifest_path
            result.success = True

        except Exception as e:
            result.errors.append(str(e))
            logger.error("Erro na coleta", error=str(e))

        finally:
            if self._start_time:
                duration = datetime.now(timezone.utc) - self._start_time
                result.duration_seconds = duration.total_seconds()

        self._log_result(result)
        return result

    def _init_manifest(self, source_type: str, **kwargs) -> None:
        self.manifest_generator = ManifestGenerator(
            case_id=self.config.case_id,
            agent_name=self.config.agent_name,
            agent_id=self.config.agent_id
        )

        metadata = self._get_source_metadata(source_type)
        self.manifest_generator.set_source(
            source_type=source_type,
            provider=self.provider_name,
            **metadata,
            **kwargs
        )

    def _save_manifest(self, source_type: str) -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        manifest_filename = f"manifest_{self.provider_name}_{source_type}_{timestamp}.json"
        manifest_path = os.path.join(self.config.output_dir, manifest_filename)
        return self.manifest_generator.save(manifest_path)

    def _get_original_path(self, local_path: str, source_type: str) -> str:
        return local_path

    def _get_file_metadata(self, file_path: str) -> dict:
        stat = os.stat(file_path)
        return {
            "collected_by": self.provider_name,
            "mtime": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
        }

    def _log_result(self, result: CollectionResult) -> None:
        if result.success:
            logger.info(
                "Coleta concluída",
                evidence_count=result.evidence_count,
                total_size_mb=round(result.total_size_bytes / (1024 * 1024), 2),
                duration_seconds=round(result.duration_seconds, 2)
            )
        else:
            logger.error("Coleta falhou", errors=result.errors)


class AuthenticationError(Exception):
    """Erro de autenticação."""
    pass


class CollectionError(Exception):
    """Erro durante coleta."""
    pass

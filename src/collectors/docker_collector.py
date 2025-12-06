"""
Coletor de Evidências Docker
============================

Coleta logs e metadados de containers Docker.

Pré-requisitos:
- Docker Desktop rodando
- pip install docker

Autor: [Seu Nome]
"""

import json
import os
from datetime import datetime, timezone
from typing import Optional

import structlog

try:
    import docker
    from docker.errors import DockerException, NotFound, APIError
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False

from .base import (
    AuthenticationError,
    BaseCollector,
    CollectionConfig,
    CollectionError,
)

logger = structlog.get_logger(__name__)


class DockerCollector(BaseCollector):
    """
    Coletor de evidências para Docker.
    
    Fontes suportadas:
    - container_logs: Logs de containers
    - container_inspect: Metadados detalhados
    - image_info: Informações de imagens
    - network_info: Configurações de rede
    - all_containers: Coleta completa
    """
    
    SOURCES = [
        'container_logs',
        'container_inspect',
        'image_info',
        'network_info',
        'all_containers'
    ]
    
    def __init__(self, config: CollectionConfig):
        if not DOCKER_AVAILABLE:
            raise ImportError("SDK Docker não instalado. Execute: pip install docker")
        
        super().__init__(config)
        self._client: Optional[docker.DockerClient] = None
    
    @property
    def provider_name(self) -> str:
        return "docker"
    
    @property
    def supported_sources(self) -> list[str]:
        return self.SOURCES
    
    def _authenticate(self) -> bool:
        try:
            self._client = docker.from_env()
            info = self._client.info()
            
            logger.info(
                "Conectado ao Docker",
                version=info.get('ServerVersion'),
                containers=info.get('ContainersRunning', 0)
            )
            return True
            
        except DockerException as e:
            raise AuthenticationError(f"Erro ao conectar ao Docker: {e}")
    
    def _get_source_metadata(self, source_type: str) -> dict:
        info = self._client.info()
        return {
            "docker_version": info.get('ServerVersion'),
            "os": info.get('OperatingSystem'),
            "containers_running": info.get('ContainersRunning')
        }
    
    def _collect_source(self, source_type: str, **kwargs) -> list[str]:
        collectors = {
            'container_logs': self._collect_container_logs,
            'container_inspect': self._collect_container_inspect,
            'image_info': self._collect_image_info,
            'network_info': self._collect_network_info,
            'all_containers': self._collect_all_containers
        }
        return collectors[source_type](**kwargs)
    
    def _collect_container_logs(
        self,
        container_id: str,
        tail: int = 10000,
        **kwargs
    ) -> list[str]:
        """Coleta logs de um container."""
        collected_files = []
        
        try:
            container = self._client.containers.get(container_id)
            logs = container.logs(stdout=True, stderr=True, timestamps=True, tail=tail)
            
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            safe_name = container.name.replace('/', '_')
            output_file = os.path.join(
                self.config.output_dir,
                f"docker_logs_{safe_name}_{timestamp}.log"
            )
            
            with open(output_file, 'wb') as f:
                f.write(logs)
            
            collected_files.append(output_file)
            logger.info("Logs coletados", container=container.name)
            
        except NotFound:
            raise CollectionError(f"Container não encontrado: {container_id}")
        
        return collected_files
    
    def _collect_container_inspect(self, container_id: str, **kwargs) -> list[str]:
        """Coleta metadados de um container (docker inspect)."""
        collected_files = []
        
        try:
            container = self._client.containers.get(container_id)
            inspect_data = self._client.api.inspect_container(container_id)
            
            inspect_data['_forensic_metadata'] = {
                'collected_at': datetime.now(timezone.utc).isoformat(),
                'case_id': self.config.case_id
            }
            
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            safe_name = container.name.replace('/', '_')
            output_file = os.path.join(
                self.config.output_dir,
                f"docker_inspect_{safe_name}_{timestamp}.json"
            )
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(inspect_data, f, indent=2, default=str)
            
            collected_files.append(output_file)
            
        except NotFound:
            raise CollectionError(f"Container não encontrado: {container_id}")
        
        return collected_files
    
    def _collect_image_info(self, **kwargs) -> list[str]:
        """Coleta informações de imagens Docker."""
        collected_files = []
        
        images = self._client.images.list()
        images_data = []
        
        for image in images:
            images_data.append({
                'id': image.id,
                'short_id': image.short_id,
                'tags': image.tags,
                'created': image.attrs.get('Created'),
                'size': image.attrs.get('Size')
            })
        
        if images_data:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(
                self.config.output_dir,
                f"docker_images_{timestamp}.json"
            )
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(images_data, f, indent=2)
            
            collected_files.append(output_file)
        
        return collected_files
    
    def _collect_network_info(self, **kwargs) -> list[str]:
        """Coleta informações de redes Docker."""
        collected_files = []
        
        networks = self._client.networks.list()
        networks_data = []
        
        for network in networks:
            networks_data.append({
                'id': network.id,
                'name': network.name,
                'driver': network.attrs.get('Driver'),
                'scope': network.attrs.get('Scope'),
                'containers': network.attrs.get('Containers')
            })
        
        if networks_data:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(
                self.config.output_dir,
                f"docker_networks_{timestamp}.json"
            )
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(networks_data, f, indent=2)
            
            collected_files.append(output_file)
        
        return collected_files
    
    def _collect_all_containers(self, include_stopped: bool = True, **kwargs) -> list[str]:
        """Coleta logs e inspect de TODOS os containers."""
        collected_files = []
        
        containers = self._client.containers.list(all=include_stopped)
        logger.info(f"Coletando {len(containers)} containers")
        
        for container in containers:
            try:
                collected_files.extend(
                    self._collect_container_logs(container_id=container.id, **kwargs)
                )
                collected_files.extend(
                    self._collect_container_inspect(container_id=container.id)
                )
            except Exception as e:
                logger.warning(f"Erro no container {container.name}: {e}")
        
        collected_files.extend(self._collect_image_info())
        collected_files.extend(self._collect_network_info())
        
        return collected_files


import json
import os
from datetime import datetime, timezone, timedelta
from typing import Optional, List

import structlog

try:
    from google.cloud import logging as cloud_logging
    from google.cloud import storage
    from google.cloud import compute_v1
    from google.auth import default as google_auth_default
    from google.auth.exceptions import DefaultCredentialsError
    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False

from .base import (
    AuthenticationError,
    BaseCollector,
    CollectionConfig,
    CollectionError,
)

logger = structlog.get_logger(__name__)


class GCPCollector(BaseCollector):

    SOURCES = [
        'cloud_logging',
        'gcs_logs',
        'compute_metadata',
        'all'
    ]

    def __init__(
        self,
        config: CollectionConfig,
        project_id: str,
        credentials_path: Optional[str] = None
    ):
       
        if not GCP_AVAILABLE:
            raise ImportError(
                "SDKs GCP não instalados. Execute: "
                "pip install google-cloud-logging google-cloud-storage google-cloud-compute"
            )

        super().__init__(config)

        self.project_id = project_id
        self._credentials_path = credentials_path

        # Clientes GCP (inicializados na autenticação)
        self._logging_client = None
        self._storage_client = None
        self._compute_client = None

    @property
    def provider_name(self) -> str:
        return "gcp"

    @property
    def supported_sources(self) -> list[str]:
        return self.SOURCES

    def _authenticate(self) -> bool:
        """Autentica com o GCP usando credenciais configuradas."""
        try:
            # Configurar credenciais se fornecido caminho
            if self._credentials_path:
                os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = self._credentials_path

            # Verificar credenciais padrão
            credentials, project = google_auth_default()

            # Inicializar clientes
            self._logging_client = cloud_logging.Client(project=self.project_id)
            self._storage_client = storage.Client(project=self.project_id)
            self._compute_client = compute_v1.InstancesClient()

            logger.info(
                "Autenticado no GCP",
                project_id=self.project_id
            )
            return True

        except DefaultCredentialsError:
            raise AuthenticationError(
                "Credenciais GCP não encontradas. Execute 'gcloud auth application-default login' "
                "ou defina GOOGLE_APPLICATION_CREDENTIALS."
            )
        except Exception as e:
            raise AuthenticationError(f"Erro de autenticação GCP: {e}")

    def _get_source_metadata(self, source_type: str) -> dict:
        """Retorna metadados da fonte GCP."""
        return {
            "project_id": self.project_id,
            "cloud": "GCP"
        }

    def _collect_source(self, source_type: str, **kwargs) -> list[str]:
        """Roteia a coleta para o método apropriado."""
        collectors = {
            'cloud_logging': self._collect_cloud_logging,
            'gcs_logs': self._collect_gcs_logs,
            'compute_metadata': self._collect_compute_metadata,
            'all': self._collect_all
        }
        return collectors[source_type](**kwargs)

    def _collect_cloud_logging(
        self,
        log_filter: str = "",
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        max_entries: int = 1000,
        **kwargs
    ) -> list[str]:
        """
        Coleta logs do Cloud Logging.

        Args:
            log_filter: Filtro de logs (sintaxe do Cloud Logging)
            start_time: Início do período
            end_time: Fim do período
            max_entries: Número máximo de entradas

        Returns:
            Lista de caminhos dos arquivos coletados
        """
        collected_files = []

        # Definir período padrão (últimas 24 horas)
        if end_time is None:
            end_time = datetime.now(timezone.utc)
        if start_time is None:
            start_time = end_time - timedelta(hours=24)

        logger.info(
            "Coletando Cloud Logging",
            start_time=start_time.isoformat(),
            filter=log_filter or "(none)"
        )

        try:
            # Construir filtro de tempo
            time_filter = (
                f'timestamp >= "{start_time.isoformat()}" AND '
                f'timestamp <= "{end_time.isoformat()}"'
            )

            # Combinar com filtro do usuário
            if log_filter:
                full_filter = f"({log_filter}) AND {time_filter}"
            else:
                full_filter = time_filter

            # Coletar entradas de log
            entries = []

            for entry in self._logging_client.list_entries(
                filter_=full_filter,
                max_results=max_entries,
                order_by=cloud_logging.DESCENDING
            ):
                entry_data = {
                    'logName': entry.log_name,
                    'timestamp': entry.timestamp.isoformat() if entry.timestamp else None,
                    'severity': entry.severity if entry.severity else None,
                    'insertId': entry.insert_id,
                    'resource': {
                        'type': entry.resource.type if entry.resource else None,
                        'labels': dict(entry.resource.labels) if entry.resource and entry.resource.labels else {}
                    },
                    'labels': dict(entry.labels) if entry.labels else {},
                    'payload': None
                }

                # Extrair payload baseado no tipo
                if entry.payload:
                    if hasattr(entry, 'text_payload') and entry.text_payload:
                        entry_data['payload'] = entry.text_payload
                    elif hasattr(entry, 'json_payload') and entry.json_payload:
                        entry_data['payload'] = dict(entry.json_payload)
                    elif hasattr(entry, 'proto_payload') and entry.proto_payload:
                        entry_data['payload'] = str(entry.proto_payload)
                    else:
                        entry_data['payload'] = str(entry.payload)

                entries.append(entry_data)

            if entries:
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                output_file = os.path.join(
                    self.config.output_dir,
                    f"gcp_cloud_logging_{self.project_id}_{timestamp}.json"
                )

                output_data = {
                    '_metadata': {
                        'source': 'cloud_logging',
                        'project_id': self.project_id,
                        'filter': log_filter,
                        'start_time': start_time.isoformat(),
                        'end_time': end_time.isoformat(),
                        'entry_count': len(entries),
                        'collected_at': datetime.now(timezone.utc).isoformat()
                    },
                    'entries': entries
                }

                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(output_data, f, indent=2, ensure_ascii=False, default=str)

                collected_files.append(output_file)
                logger.info(f"Cloud Logging: {len(entries)} entradas coletadas")
            else:
                logger.warning("Cloud Logging: nenhuma entrada encontrada")

        except Exception as e:
            raise CollectionError(f"Erro ao coletar Cloud Logging: {e}")

        return collected_files

    def _collect_gcs_logs(
        self,
        bucket_name: str,
        prefix: str = "",
        max_blobs: int = 100,
        **kwargs
    ) -> list[str]:
        """
        Coleta logs de um bucket Cloud Storage.

        Args:
            bucket_name: Nome do bucket
            prefix: Prefixo para filtrar objetos
            max_blobs: Número máximo de blobs a baixar

        Returns:
            Lista de caminhos dos arquivos coletados
        """
        collected_files = []

        logger.info(
            "Coletando GCS Logs",
            bucket=bucket_name,
            prefix=prefix
        )

        try:
            bucket = self._storage_client.bucket(bucket_name)

            blobs_data = []
            blob_count = 0

            for blob in bucket.list_blobs(prefix=prefix):
                if blob_count >= max_blobs:
                    break

                try:
                    # Baixar conteúdo
                    content = blob.download_as_bytes()

                    # Tentar decodificar como texto
                    try:
                        content_str = content.decode('utf-8')
                    except UnicodeDecodeError:
                        content_str = f"[Binary content, {len(content)} bytes]"

                    blobs_data.append({
                        'name': blob.name,
                        'size': blob.size,
                        'updated': blob.updated.isoformat() if blob.updated else None,
                        'content_type': blob.content_type,
                        'md5_hash': blob.md5_hash,
                        'content': content_str if len(content_str) < 1000000 else f"[Content too large: {len(content_str)} chars]"
                    })
                    blob_count += 1

                except Exception as e:
                    logger.warning(f"Erro ao baixar blob {blob.name}: {e}")

            if blobs_data:
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                output_file = os.path.join(
                    self.config.output_dir,
                    f"gcp_gcs_{bucket_name}_{timestamp}.json"
                )

                output_data = {
                    '_metadata': {
                        'source': 'gcs_logs',
                        'project_id': self.project_id,
                        'bucket': bucket_name,
                        'prefix': prefix,
                        'blob_count': len(blobs_data),
                        'collected_at': datetime.now(timezone.utc).isoformat()
                    },
                    'blobs': blobs_data
                }

                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(output_data, f, indent=2, ensure_ascii=False)

                collected_files.append(output_file)
                logger.info(f"GCS Logs: {len(blobs_data)} blobs coletados")
            else:
                logger.warning("GCS Logs: nenhum blob encontrado")

        except Exception as e:
            raise CollectionError(f"Erro ao coletar GCS Logs: {e}")

        return collected_files

    def _collect_compute_metadata(
        self,
        zone: Optional[str] = None,
        instance_names: Optional[List[str]] = None,
        **kwargs
    ) -> list[str]:
        """
        Coleta metadados de instâncias Compute Engine.

        Args:
            zone: Zona específica (ex: us-central1-a). Se None, busca em todas.
            instance_names: Lista de nomes de instâncias específicas

        Returns:
            Lista de caminhos dos arquivos coletados
        """
        collected_files = []

        logger.info(
            "Coletando Compute Metadata",
            zone=zone or "all",
            instances=instance_names or "all"
        )

        try:
            instances_data = []

            if zone:
                # Listar instâncias em uma zona específica
                zones_to_check = [zone]
            else:
                # Listar todas as instâncias (agregado)
                zones_to_check = None

            # Usar aggregated_list para buscar em todas as zonas
            if zones_to_check is None:
                request = compute_v1.AggregatedListInstancesRequest(project=self.project_id)
                agg_list = self._compute_client.aggregated_list(request=request)

                for zone_name, instances_scoped_list in agg_list:
                    if instances_scoped_list.instances:
                        for instance in instances_scoped_list.instances:
                            if instance_names and instance.name not in instance_names:
                                continue

                            instance_data = self._serialize_compute_instance(instance, zone_name)
                            instances_data.append(instance_data)
            else:
                # Listar em zona específica
                for z in zones_to_check:
                    request = compute_v1.ListInstancesRequest(project=self.project_id, zone=z)

                    for instance in self._compute_client.list(request=request):
                        if instance_names and instance.name not in instance_names:
                            continue

                        instance_data = self._serialize_compute_instance(instance, z)
                        instances_data.append(instance_data)

            if instances_data:
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                zone_suffix = f"_{zone}" if zone else ""
                output_file = os.path.join(
                    self.config.output_dir,
                    f"gcp_compute_metadata{zone_suffix}_{timestamp}.json"
                )

                output_data = {
                    '_metadata': {
                        'source': 'compute_metadata',
                        'project_id': self.project_id,
                        'zone': zone,
                        'instance_count': len(instances_data),
                        'collected_at': datetime.now(timezone.utc).isoformat()
                    },
                    'instances': instances_data
                }

                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(output_data, f, indent=2, ensure_ascii=False)

                collected_files.append(output_file)
                logger.info(f"Compute Metadata: {len(instances_data)} instâncias coletadas")
            else:
                logger.warning("Compute Metadata: nenhuma instância encontrada")

        except Exception as e:
            raise CollectionError(f"Erro ao coletar Compute Metadata: {e}")

        return collected_files

    def _serialize_compute_instance(self, instance, zone: str) -> dict:
        """Serializa uma instância Compute Engine para dicionário."""
        return {
            'id': str(instance.id),
            'name': instance.name,
            'zone': zone.split('/')[-1] if '/' in zone else zone,
            'machineType': instance.machine_type.split('/')[-1] if instance.machine_type else None,
            'status': instance.status,
            'creationTimestamp': instance.creation_timestamp,
            'description': instance.description,
            'cpuPlatform': instance.cpu_platform,
            'labels': dict(instance.labels) if instance.labels else {},
            'metadata': {
                'items': [
                    {'key': item.key, 'value': item.value[:100] + '...' if len(item.value or '') > 100 else item.value}
                    for item in (instance.metadata.items if instance.metadata and instance.metadata.items else [])
                ]
            },
            'networkInterfaces': [
                {
                    'name': ni.name,
                    'network': ni.network.split('/')[-1] if ni.network else None,
                    'subnetwork': ni.subnetwork.split('/')[-1] if ni.subnetwork else None,
                    'networkIP': ni.network_i_p,
                    'accessConfigs': [
                        {
                            'name': ac.name,
                            'natIP': ac.nat_i_p,
                            'type': ac.type_
                        }
                        for ac in (ni.access_configs or [])
                    ]
                }
                for ni in (instance.network_interfaces or [])
            ],
            'disks': [
                {
                    'deviceName': disk.device_name,
                    'source': disk.source.split('/')[-1] if disk.source else None,
                    'boot': disk.boot,
                    'autoDelete': disk.auto_delete,
                    'mode': disk.mode
                }
                for disk in (instance.disks or [])
            ],
            'serviceAccounts': [
                {
                    'email': sa.email,
                    'scopes': list(sa.scopes) if sa.scopes else []
                }
                for sa in (instance.service_accounts or [])
            ],
            'tags': list(instance.tags.items) if instance.tags and instance.tags.items else []
        }

    def _collect_all(self, **kwargs) -> list[str]:
        """
        Coleta todas as fontes disponíveis.
        """
        collected_files = []

        # Cloud Logging (sempre disponível)
        try:
            collected_files.extend(self._collect_cloud_logging(**kwargs))
        except Exception as e:
            logger.warning(f"Falha ao coletar Cloud Logging: {e}")

        # Compute Metadata
        try:
            collected_files.extend(self._collect_compute_metadata(**kwargs))
        except Exception as e:
            logger.warning(f"Falha ao coletar Compute Metadata: {e}")

        # GCS Logs (requer bucket_name)
        if 'bucket_name' in kwargs:
            try:
                collected_files.extend(self._collect_gcs_logs(**kwargs))
            except Exception as e:
                logger.warning(f"Falha ao coletar GCS Logs: {e}")

        return collected_files

    def _get_original_path(self, local_path: str, source_type: str) -> str:
        """Retorna o caminho original da evidência no GCP."""
        return f"gcp://{self.project_id}/{source_type}"

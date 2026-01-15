
import json
import os
from datetime import datetime, timezone, timedelta
from typing import Optional, List

import structlog

try:
    from azure.identity import DefaultAzureCredential, ClientSecretCredential
    from azure.mgmt.monitor import MonitorManagementClient
    from azure.mgmt.compute import ComputeManagementClient
    from azure.storage.blob import BlobServiceClient
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

from .base import (
    AuthenticationError,
    BaseCollector,
    CollectionConfig,
    CollectionError,
)

logger = structlog.get_logger(__name__)


class AzureCollector(BaseCollector):

    SOURCES = [
        'activity_log',
        'blob_storage',
        'vm_metadata',
        'nsg_flow_logs',
        'all'
    ]

    def __init__(
        self,
        config: CollectionConfig,
        subscription_id: str,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None
    ):
        """
        Inicializa o coletor Azure.

        Args:
            config: Configuração da coleta
            subscription_id: ID da assinatura Azure
            tenant_id: ID do tenant (para Service Principal)
            client_id: ID do aplicativo (para Service Principal)
            client_secret: Secret do aplicativo (para Service Principal)
        """
        if not AZURE_AVAILABLE:
            raise ImportError(
                "SDKs Azure não instalados. Execute: "
                "pip install azure-identity azure-mgmt-monitor azure-mgmt-compute azure-storage-blob"
            )

        super().__init__(config)

        self.subscription_id = subscription_id
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret

        # Clientes Azure (inicializados na autenticação)
        self._credential = None
        self._monitor_client = None
        self._compute_client = None

    @property
    def provider_name(self) -> str:
        return "azure"

    @property
    def supported_sources(self) -> list[str]:
        return self.SOURCES

    def _authenticate(self) -> bool:
        """Autentica com o Azure usando credenciais configuradas."""
        try:
            # Usar Service Principal se fornecido, caso contrário DefaultAzureCredential
            if self._tenant_id and self._client_id and self._client_secret:
                self._credential = ClientSecretCredential(
                    tenant_id=self._tenant_id,
                    client_id=self._client_id,
                    client_secret=self._client_secret
                )
                auth_method = "Service Principal"
            else:
                self._credential = DefaultAzureCredential()
                auth_method = "Default Credential"

            # Inicializar clientes
            self._monitor_client = MonitorManagementClient(
                credential=self._credential,
                subscription_id=self.subscription_id
            )

            self._compute_client = ComputeManagementClient(
                credential=self._credential,
                subscription_id=self.subscription_id
            )

            # Testar autenticação listando um recurso
            # (a operação falhará se as credenciais estiverem inválidas)
            logger.info(
                "Autenticado no Azure",
                subscription_id=self.subscription_id[:8] + "...",
                auth_method=auth_method
            )
            return True

        except Exception as e:
            raise AuthenticationError(f"Erro de autenticação Azure: {e}")

    def _get_source_metadata(self, source_type: str) -> dict:
        """Retorna metadados da fonte Azure."""
        return {
            "subscription_id": self.subscription_id,
            "cloud": "AzureCloud"
        }

    def _collect_source(self, source_type: str, **kwargs) -> list[str]:
        """Roteia a coleta para o método apropriado."""
        collectors = {
            'activity_log': self._collect_activity_log,
            'blob_storage': self._collect_blob_storage,
            'vm_metadata': self._collect_vm_metadata,
            'nsg_flow_logs': self._collect_nsg_flow_logs,
            'all': self._collect_all
        }
        return collectors[source_type](**kwargs)

    def _collect_activity_log(
        self,
        resource_group: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        max_events: int = 1000,
        **kwargs
    ) -> list[str]:
        """
        Coleta Azure Activity Log.

        Args:
            resource_group: Filtrar por Resource Group (opcional)
            start_time: Início do período
            end_time: Fim do período
            max_events: Número máximo de eventos

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
            "Coletando Activity Log",
            resource_group=resource_group or "all",
            start_time=start_time.isoformat()
        )

        try:
            # Construir filtro OData
            filter_parts = [
                f"eventTimestamp ge '{start_time.isoformat()}'",
                f"eventTimestamp le '{end_time.isoformat()}'"
            ]

            if resource_group:
                filter_parts.append(f"resourceGroupName eq '{resource_group}'")

            filter_str = " and ".join(filter_parts)

            # Coletar eventos
            events = []
            activity_logs = self._monitor_client.activity_logs.list(filter=filter_str)

            for event in activity_logs:
                if len(events) >= max_events:
                    break

                event_data = {
                    'id': event.id,
                    'correlationId': event.correlation_id,
                    'eventTimestamp': event.event_timestamp.isoformat() if event.event_timestamp else None,
                    'submissionTimestamp': event.submission_timestamp.isoformat() if event.submission_timestamp else None,
                    'level': str(event.level) if event.level else None,
                    'operationName': event.operation_name.value if event.operation_name else None,
                    'status': event.status.value if event.status else None,
                    'caller': event.caller,
                    'resourceGroupName': event.resource_group_name,
                    'resourceId': event.resource_id,
                    'resourceType': event.resource_type.value if event.resource_type else None,
                    'category': event.category.value if event.category else None,
                    'claims': dict(event.claims) if event.claims else None,
                    'httpRequest': {
                        'clientRequestId': event.http_request.client_request_id if event.http_request else None,
                        'clientIpAddress': event.http_request.client_ip_address if event.http_request else None,
                        'method': event.http_request.method if event.http_request else None
                    } if event.http_request else None
                }
                events.append(event_data)

            if events:
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                rg_suffix = f"_{resource_group}" if resource_group else ""
                output_file = os.path.join(
                    self.config.output_dir,
                    f"azure_activity_log{rg_suffix}_{timestamp}.json"
                )

                output_data = {
                    '_metadata': {
                        'source': 'activity_log',
                        'subscription_id': self.subscription_id,
                        'resource_group': resource_group,
                        'start_time': start_time.isoformat(),
                        'end_time': end_time.isoformat(),
                        'event_count': len(events),
                        'collected_at': datetime.now(timezone.utc).isoformat()
                    },
                    'events': events
                }

                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(output_data, f, indent=2, ensure_ascii=False)

                collected_files.append(output_file)
                logger.info(f"Activity Log: {len(events)} eventos coletados")
            else:
                logger.warning("Activity Log: nenhum evento encontrado")

        except Exception as e:
            raise CollectionError(f"Erro ao coletar Activity Log: {e}")

        return collected_files

    def _collect_blob_storage(
        self,
        account_url: str,
        container_name: str,
        prefix: str = "",
        max_blobs: int = 100,
        **kwargs
    ) -> list[str]:
        """
        Coleta logs de um Azure Blob Storage.

        Args:
            account_url: URL da conta de storage (ex: https://account.blob.core.windows.net)
            container_name: Nome do container
            prefix: Prefixo para filtrar blobs
            max_blobs: Número máximo de blobs a baixar

        Returns:
            Lista de caminhos dos arquivos coletados
        """
        collected_files = []

        logger.info(
            "Coletando Blob Storage",
            account_url=account_url,
            container=container_name,
            prefix=prefix
        )

        try:
            # Criar cliente do Blob Storage
            blob_service_client = BlobServiceClient(
                account_url=account_url,
                credential=self._credential
            )

            container_client = blob_service_client.get_container_client(container_name)

            # Listar e baixar blobs
            blobs_data = []
            blob_count = 0

            for blob in container_client.list_blobs(name_starts_with=prefix):
                if blob_count >= max_blobs:
                    break

                # Baixar conteúdo do blob
                blob_client = container_client.get_blob_client(blob.name)

                try:
                    content = blob_client.download_blob().readall()

                    # Tentar decodificar como texto
                    try:
                        content_str = content.decode('utf-8')
                    except UnicodeDecodeError:
                        content_str = f"[Binary content, {len(content)} bytes]"

                    blobs_data.append({
                        'name': blob.name,
                        'size': blob.size,
                        'last_modified': blob.last_modified.isoformat() if blob.last_modified else None,
                        'content_type': blob.content_settings.content_type if blob.content_settings else None,
                        'content': content_str if len(content_str) < 1000000 else f"[Content too large: {len(content_str)} chars]"
                    })
                    blob_count += 1

                except Exception as e:
                    logger.warning(f"Erro ao baixar blob {blob.name}: {e}")

            if blobs_data:
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                output_file = os.path.join(
                    self.config.output_dir,
                    f"azure_blob_{container_name}_{timestamp}.json"
                )

                output_data = {
                    '_metadata': {
                        'source': 'blob_storage',
                        'account_url': account_url,
                        'container': container_name,
                        'prefix': prefix,
                        'blob_count': len(blobs_data),
                        'collected_at': datetime.now(timezone.utc).isoformat()
                    },
                    'blobs': blobs_data
                }

                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(output_data, f, indent=2, ensure_ascii=False)

                collected_files.append(output_file)
                logger.info(f"Blob Storage: {len(blobs_data)} blobs coletados")
            else:
                logger.warning("Blob Storage: nenhum blob encontrado")

        except Exception as e:
            raise CollectionError(f"Erro ao coletar Blob Storage: {e}")

        return collected_files

    def _collect_vm_metadata(
        self,
        resource_group: Optional[str] = None,
        vm_names: Optional[List[str]] = None,
        **kwargs
    ) -> list[str]:
        """
        Coleta metadados de VMs Azure.

        Args:
            resource_group: Filtrar por Resource Group
            vm_names: Lista de nomes de VMs específicas

        Returns:
            Lista de caminhos dos arquivos coletados
        """
        collected_files = []

        logger.info(
            "Coletando VM Metadata",
            resource_group=resource_group or "all",
            vm_names=vm_names or "all"
        )

        try:
            vms_data = []

            # Listar VMs
            if resource_group:
                vms = self._compute_client.virtual_machines.list(resource_group)
            else:
                vms = self._compute_client.virtual_machines.list_all()

            for vm in vms:
                # Filtrar por nome se especificado
                if vm_names and vm.name not in vm_names:
                    continue

                # Obter detalhes da VM (instance view para status)
                vm_rg = vm.id.split('/')[4]  # Extrair resource group do ID

                try:
                    instance_view = self._compute_client.virtual_machines.instance_view(
                        resource_group_name=vm_rg,
                        vm_name=vm.name
                    )

                    statuses = [
                        {'code': s.code, 'displayStatus': s.display_status}
                        for s in (instance_view.statuses or [])
                    ]
                except Exception:
                    statuses = []

                vm_data = {
                    'id': vm.id,
                    'name': vm.name,
                    'location': vm.location,
                    'resourceGroup': vm_rg,
                    'vmSize': vm.hardware_profile.vm_size if vm.hardware_profile else None,
                    'osType': vm.storage_profile.os_disk.os_type if vm.storage_profile and vm.storage_profile.os_disk else None,
                    'osPublisher': vm.storage_profile.image_reference.publisher if vm.storage_profile and vm.storage_profile.image_reference else None,
                    'osOffer': vm.storage_profile.image_reference.offer if vm.storage_profile and vm.storage_profile.image_reference else None,
                    'osSku': vm.storage_profile.image_reference.sku if vm.storage_profile and vm.storage_profile.image_reference else None,
                    'provisioningState': vm.provisioning_state,
                    'statuses': statuses,
                    'networkInterfaces': [
                        {'id': nic.id}
                        for nic in (vm.network_profile.network_interfaces or [])
                    ] if vm.network_profile else [],
                    'tags': dict(vm.tags) if vm.tags else {}
                }
                vms_data.append(vm_data)

            if vms_data:
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                rg_suffix = f"_{resource_group}" if resource_group else ""
                output_file = os.path.join(
                    self.config.output_dir,
                    f"azure_vm_metadata{rg_suffix}_{timestamp}.json"
                )

                output_data = {
                    '_metadata': {
                        'source': 'vm_metadata',
                        'subscription_id': self.subscription_id,
                        'resource_group': resource_group,
                        'vm_count': len(vms_data),
                        'collected_at': datetime.now(timezone.utc).isoformat()
                    },
                    'virtual_machines': vms_data
                }

                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(output_data, f, indent=2, ensure_ascii=False)

                collected_files.append(output_file)
                logger.info(f"VM Metadata: {len(vms_data)} VMs coletadas")
            else:
                logger.warning("VM Metadata: nenhuma VM encontrada")

        except Exception as e:
            raise CollectionError(f"Erro ao coletar VM Metadata: {e}")

        return collected_files

    def _collect_nsg_flow_logs(
        self,
        account_url: str,
        container_name: str = "insights-logs-networksecuritygroupflowevent",
        prefix: str = "",
        max_blobs: int = 50,
        **kwargs
    ) -> list[str]:
        """
        Coleta NSG Flow Logs do Blob Storage.

        NSG Flow Logs são armazenados em Blob Storage com estrutura específica.

        Args:
            account_url: URL da conta de storage
            container_name: Nome do container (padrão do Azure)
            prefix: Prefixo para filtrar
            max_blobs: Número máximo de blobs

        Returns:
            Lista de caminhos dos arquivos coletados
        """
        # NSG Flow Logs usam o mesmo mecanismo de Blob Storage
        collected_files = self._collect_blob_storage(
            account_url=account_url,
            container_name=container_name,
            prefix=prefix,
            max_blobs=max_blobs,
            **kwargs
        )

        # Renomear para indicar que são NSG Flow Logs
        renamed_files = []
        for file_path in collected_files:
            new_path = file_path.replace('azure_blob', 'azure_nsg_flow_logs')
            if file_path != new_path:
                os.rename(file_path, new_path)
                renamed_files.append(new_path)
            else:
                renamed_files.append(file_path)

        return renamed_files

    def _collect_all(self, **kwargs) -> list[str]:
        """
        Coleta todas as fontes disponíveis.
        """
        collected_files = []

        # Activity Log (sempre disponível)
        try:
            collected_files.extend(self._collect_activity_log(**kwargs))
        except Exception as e:
            logger.warning(f"Falha ao coletar Activity Log: {e}")

        # VM Metadata
        try:
            collected_files.extend(self._collect_vm_metadata(**kwargs))
        except Exception as e:
            logger.warning(f"Falha ao coletar VM Metadata: {e}")

        # Blob Storage (requer parâmetros)
        if 'account_url' in kwargs and 'container_name' in kwargs:
            try:
                collected_files.extend(self._collect_blob_storage(**kwargs))
            except Exception as e:
                logger.warning(f"Falha ao coletar Blob Storage: {e}")

        return collected_files

    def _get_original_path(self, local_path: str, source_type: str) -> str:
        """Retorna o caminho original da evidência no Azure."""
        return f"azure://{self.subscription_id}/{source_type}"

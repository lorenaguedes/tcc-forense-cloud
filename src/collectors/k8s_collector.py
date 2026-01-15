"""
Coletor de Evidências Kubernetes
================================

Coleta logs, eventos e metadados de clusters Kubernetes para análise forense.

Fontes suportadas:
- pod_logs: Logs de containers em pods
- events: Eventos do cluster
- resources: Metadados de recursos (pods, deployments, services, etc.)
- configmaps: ConfigMaps e Secrets (metadados apenas)
- all: Coleta completa do namespace

Pré-requisitos:
- pip install kubernetes
- kubectl configurado (~/.kube/config) ou running in-cluster

Referências:
- Kubernetes API: https://kubernetes.io/docs/reference/kubernetes-api/
- NIST SP 800-86: Guide to Integrating Forensic Techniques

"""

import json
import os
from datetime import datetime, timezone, timedelta
from typing import Optional, List

import structlog

try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException
    from kubernetes.config.config_exception import ConfigException
    K8S_AVAILABLE = True
except ImportError:
    K8S_AVAILABLE = False

from .base import (
    AuthenticationError,
    BaseCollector,
    CollectionConfig,
    CollectionError,
)

logger = structlog.get_logger(__name__)


class KubernetesCollector(BaseCollector):
    """
    Coletor de evidências para Kubernetes.

    Fontes suportadas:
    - pod_logs: Logs de pods/containers
    - events: Eventos do cluster (warnings, errors, etc.)
    - resources: Metadados de recursos K8s
    - configmaps: ConfigMaps (sem dados sensíveis)
    - secrets_metadata: Metadados de Secrets (sem valores)
    - network_policies: Políticas de rede
    - all: Coleta completa do namespace

    Example:
        >>> config = CollectionConfig(
        ...     case_id="CASO-2025-001",
        ...     agent_name="Perito",
        ...     agent_id="PER001"
        ... )
        >>> collector = KubernetesCollector(config, namespace="default")
        >>> result = collector.collect("pod_logs")
    """

    SOURCES = [
        'pod_logs',
        'events',
        'resources',
        'configmaps',
        'secrets_metadata',
        'network_policies',
        'all'
    ]

    def __init__(
        self,
        config: CollectionConfig,
        namespace: str = "default",
        kubeconfig_path: Optional[str] = None,
        context: Optional[str] = None,
        in_cluster: bool = False
    ):
        """
        Inicializa o coletor Kubernetes.

        Args:
            config: Configuração da coleta
            namespace: Namespace para coletar (default: "default")
            kubeconfig_path: Caminho para kubeconfig (opcional)
            context: Contexto do kubeconfig (opcional)
            in_cluster: Se True, usa configuração in-cluster
        """
        if not K8S_AVAILABLE:
            raise ImportError(
                "SDK Kubernetes não instalado. Execute: pip install kubernetes"
            )

        super().__init__(config)

        self.namespace = namespace
        self.kubeconfig_path = kubeconfig_path
        self.context = context
        self.in_cluster = in_cluster

        # Clientes K8s (inicializados na autenticação)
        self._core_v1: Optional[client.CoreV1Api] = None
        self._apps_v1: Optional[client.AppsV1Api] = None
        self._networking_v1: Optional[client.NetworkingV1Api] = None

        self._cluster_info: dict = {}

    @property
    def provider_name(self) -> str:
        return "kubernetes"

    @property
    def supported_sources(self) -> list[str]:
        return self.SOURCES

    def _authenticate(self) -> bool:
        """Configura e autentica com o cluster Kubernetes."""
        try:
            # Carregar configuração
            if self.in_cluster:
                config.load_incluster_config()
                auth_method = "in-cluster"
            elif self.kubeconfig_path:
                config.load_kube_config(
                    config_file=self.kubeconfig_path,
                    context=self.context
                )
                auth_method = f"kubeconfig ({self.kubeconfig_path})"
            else:
                config.load_kube_config(context=self.context)
                auth_method = "default kubeconfig"

            # Inicializar clientes de API
            self._core_v1 = client.CoreV1Api()
            self._apps_v1 = client.AppsV1Api()
            self._networking_v1 = client.NetworkingV1Api()

            # Testar conexão e obter informações do cluster
            version_info = client.VersionApi().get_code()
            self._cluster_info = {
                'git_version': version_info.git_version,
                'platform': version_info.platform,
                'go_version': version_info.go_version
            }

            logger.info(
                "Conectado ao Kubernetes",
                cluster_version=version_info.git_version,
                namespace=self.namespace,
                auth_method=auth_method
            )
            return True

        except ConfigException as e:
            raise AuthenticationError(
                f"Erro de configuração Kubernetes: {e}. "
                "Verifique se kubectl está configurado (kubectl config view)"
            )
        except ApiException as e:
            raise AuthenticationError(f"Erro de API Kubernetes: {e}")
        except Exception as e:
            raise AuthenticationError(f"Erro ao conectar ao Kubernetes: {e}")

    def _get_source_metadata(self, source_type: str) -> dict:
        """Retorna metadados da fonte Kubernetes."""
        return {
            "namespace": self.namespace,
            "cluster_version": self._cluster_info.get('git_version', 'unknown'),
            "platform": self._cluster_info.get('platform', 'unknown')
        }

    def _collect_source(self, source_type: str, **kwargs) -> list[str]:
        """Roteia a coleta para o método apropriado."""
        collectors = {
            'pod_logs': self._collect_pod_logs,
            'events': self._collect_events,
            'resources': self._collect_resources,
            'configmaps': self._collect_configmaps,
            'secrets_metadata': self._collect_secrets_metadata,
            'network_policies': self._collect_network_policies,
            'all': self._collect_all
        }
        return collectors[source_type](**kwargs)

    def _collect_pod_logs(
        self,
        pod_name: Optional[str] = None,
        container_name: Optional[str] = None,
        tail_lines: int = 10000,
        since_seconds: Optional[int] = None,
        previous: bool = False,
        **kwargs
    ) -> list[str]:
        """
        Coleta logs de pods.

        Args:
            pod_name: Nome do pod específico (None = todos)
            container_name: Nome do container (None = todos)
            tail_lines: Número de linhas do final
            since_seconds: Logs dos últimos N segundos
            previous: Se True, coleta logs do container anterior (crashed)

        Returns:
            Lista de caminhos dos arquivos coletados
        """
        collected_files = []

        logger.info(
            "Coletando Pod Logs",
            namespace=self.namespace,
            pod=pod_name or "all",
            tail_lines=tail_lines
        )

        try:
            # Listar pods
            if pod_name:
                pods = [self._core_v1.read_namespaced_pod(pod_name, self.namespace)]
            else:
                pod_list = self._core_v1.list_namespaced_pod(self.namespace)
                pods = pod_list.items

            all_logs = []

            for pod in pods:
                pod_info = {
                    'pod_name': pod.metadata.name,
                    'namespace': pod.metadata.namespace,
                    'phase': pod.status.phase,
                    'containers': []
                }

                # Coletar logs de cada container
                containers = pod.spec.containers or []
                for container in containers:
                    if container_name and container.name != container_name:
                        continue

                    try:
                        log_kwargs = {
                            'name': pod.metadata.name,
                            'namespace': self.namespace,
                            'container': container.name,
                            'tail_lines': tail_lines,
                            'timestamps': True
                        }

                        if since_seconds:
                            log_kwargs['since_seconds'] = since_seconds
                        if previous:
                            log_kwargs['previous'] = True

                        logs = self._core_v1.read_namespaced_pod_log(**log_kwargs)

                        pod_info['containers'].append({
                            'container_name': container.name,
                            'image': container.image,
                            'log_lines': len(logs.split('\n')) if logs else 0,
                            'logs': logs
                        })

                    except ApiException as e:
                        if e.status == 400:  # Container not ready
                            pod_info['containers'].append({
                                'container_name': container.name,
                                'image': container.image,
                                'error': 'Container not ready or no logs available'
                            })
                        else:
                            logger.warning(f"Erro ao coletar logs de {pod.metadata.name}/{container.name}: {e}")

                all_logs.append(pod_info)

            if all_logs:
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                output_file = os.path.join(
                    self.config.output_dir,
                    f"k8s_pod_logs_{self.namespace}_{timestamp}.json"
                )

                output_data = {
                    '_metadata': {
                        'source': 'pod_logs',
                        'namespace': self.namespace,
                        'cluster_version': self._cluster_info.get('git_version'),
                        'pod_count': len(all_logs),
                        'tail_lines': tail_lines,
                        'collected_at': datetime.now(timezone.utc).isoformat()
                    },
                    'pods': all_logs
                }

                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(output_data, f, indent=2, ensure_ascii=False)

                collected_files.append(output_file)
                total_containers = sum(len(p['containers']) for p in all_logs)
                logger.info(f"Pod Logs: {len(all_logs)} pods, {total_containers} containers coletados")
            else:
                logger.warning("Pod Logs: nenhum pod encontrado")

        except ApiException as e:
            raise CollectionError(f"Erro ao coletar Pod Logs: {e}")

        return collected_files

    def _collect_events(
        self,
        event_type: Optional[str] = None,
        involved_object_kind: Optional[str] = None,
        max_events: int = 1000,
        **kwargs
    ) -> list[str]:
        """
        Coleta eventos do cluster.

        Args:
            event_type: Filtrar por tipo (Normal, Warning)
            involved_object_kind: Filtrar por tipo de objeto (Pod, Node, etc.)
            max_events: Número máximo de eventos

        Returns:
            Lista de caminhos dos arquivos coletados
        """
        collected_files = []

        logger.info(
            "Coletando Events",
            namespace=self.namespace,
            event_type=event_type or "all"
        )

        try:
            events_list = self._core_v1.list_namespaced_event(self.namespace)

            events = []
            for event in events_list.items[:max_events]:
                # Aplicar filtros
                if event_type and event.type != event_type:
                    continue
                if involved_object_kind and event.involved_object.kind != involved_object_kind:
                    continue

                event_data = {
                    'name': event.metadata.name,
                    'namespace': event.metadata.namespace,
                    'type': event.type,
                    'reason': event.reason,
                    'message': event.message,
                    'count': event.count,
                    'first_timestamp': event.first_timestamp.isoformat() if event.first_timestamp else None,
                    'last_timestamp': event.last_timestamp.isoformat() if event.last_timestamp else None,
                    'involved_object': {
                        'kind': event.involved_object.kind,
                        'name': event.involved_object.name,
                        'namespace': event.involved_object.namespace,
                        'uid': event.involved_object.uid
                    },
                    'source': {
                        'component': event.source.component if event.source else None,
                        'host': event.source.host if event.source else None
                    }
                }
                events.append(event_data)

            if events:
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                output_file = os.path.join(
                    self.config.output_dir,
                    f"k8s_events_{self.namespace}_{timestamp}.json"
                )

                output_data = {
                    '_metadata': {
                        'source': 'events',
                        'namespace': self.namespace,
                        'cluster_version': self._cluster_info.get('git_version'),
                        'event_count': len(events),
                        'event_type_filter': event_type,
                        'collected_at': datetime.now(timezone.utc).isoformat()
                    },
                    'events': events
                }

                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(output_data, f, indent=2, ensure_ascii=False)

                collected_files.append(output_file)

                # Contar por tipo
                warnings = sum(1 for e in events if e['type'] == 'Warning')
                logger.info(f"Events: {len(events)} eventos ({warnings} warnings)")
            else:
                logger.warning("Events: nenhum evento encontrado")

        except ApiException as e:
            raise CollectionError(f"Erro ao coletar Events: {e}")

        return collected_files

    def _collect_resources(
        self,
        resource_types: Optional[List[str]] = None,
        **kwargs
    ) -> list[str]:
        """
        Coleta metadados de recursos Kubernetes.

        Args:
            resource_types: Lista de tipos (pods, deployments, services, etc.)
                           Se None, coleta todos os principais

        Returns:
            Lista de caminhos dos arquivos coletados
        """
        collected_files = []

        if resource_types is None:
            resource_types = ['pods', 'deployments', 'services', 'replicasets', 'daemonsets', 'statefulsets']

        logger.info(
            "Coletando Resources",
            namespace=self.namespace,
            types=resource_types
        )

        try:
            resources_data = {}

            # Pods
            if 'pods' in resource_types:
                pods = self._core_v1.list_namespaced_pod(self.namespace)
                resources_data['pods'] = [
                    self._serialize_pod(pod) for pod in pods.items
                ]

            # Deployments
            if 'deployments' in resource_types:
                deployments = self._apps_v1.list_namespaced_deployment(self.namespace)
                resources_data['deployments'] = [
                    self._serialize_deployment(d) for d in deployments.items
                ]

            # Services
            if 'services' in resource_types:
                services = self._core_v1.list_namespaced_service(self.namespace)
                resources_data['services'] = [
                    self._serialize_service(s) for s in services.items
                ]

            # ReplicaSets
            if 'replicasets' in resource_types:
                replicasets = self._apps_v1.list_namespaced_replica_set(self.namespace)
                resources_data['replicasets'] = [
                    self._serialize_replicaset(rs) for rs in replicasets.items
                ]

            # DaemonSets
            if 'daemonsets' in resource_types:
                daemonsets = self._apps_v1.list_namespaced_daemon_set(self.namespace)
                resources_data['daemonsets'] = [
                    self._serialize_daemonset(ds) for ds in daemonsets.items
                ]

            # StatefulSets
            if 'statefulsets' in resource_types:
                statefulsets = self._apps_v1.list_namespaced_stateful_set(self.namespace)
                resources_data['statefulsets'] = [
                    self._serialize_statefulset(ss) for ss in statefulsets.items
                ]

            if resources_data:
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                output_file = os.path.join(
                    self.config.output_dir,
                    f"k8s_resources_{self.namespace}_{timestamp}.json"
                )

                total_resources = sum(len(v) for v in resources_data.values())

                output_data = {
                    '_metadata': {
                        'source': 'resources',
                        'namespace': self.namespace,
                        'cluster_version': self._cluster_info.get('git_version'),
                        'resource_types': list(resources_data.keys()),
                        'total_resources': total_resources,
                        'collected_at': datetime.now(timezone.utc).isoformat()
                    },
                    'resources': resources_data
                }

                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(output_data, f, indent=2, ensure_ascii=False)

                collected_files.append(output_file)
                logger.info(f"Resources: {total_resources} recursos coletados")
            else:
                logger.warning("Resources: nenhum recurso encontrado")

        except ApiException as e:
            raise CollectionError(f"Erro ao coletar Resources: {e}")

        return collected_files

    def _collect_configmaps(self, **kwargs) -> list[str]:
        """Coleta ConfigMaps do namespace."""
        collected_files = []

        logger.info("Coletando ConfigMaps", namespace=self.namespace)

        try:
            configmaps = self._core_v1.list_namespaced_config_map(self.namespace)

            cms_data = []
            for cm in configmaps.items:
                cms_data.append({
                    'name': cm.metadata.name,
                    'namespace': cm.metadata.namespace,
                    'creation_timestamp': cm.metadata.creation_timestamp.isoformat() if cm.metadata.creation_timestamp else None,
                    'labels': dict(cm.metadata.labels) if cm.metadata.labels else {},
                    'annotations': dict(cm.metadata.annotations) if cm.metadata.annotations else {},
                    'data_keys': list(cm.data.keys()) if cm.data else [],
                    'data': dict(cm.data) if cm.data else {}  # Inclui dados (não são sensíveis)
                })

            if cms_data:
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                output_file = os.path.join(
                    self.config.output_dir,
                    f"k8s_configmaps_{self.namespace}_{timestamp}.json"
                )

                output_data = {
                    '_metadata': {
                        'source': 'configmaps',
                        'namespace': self.namespace,
                        'configmap_count': len(cms_data),
                        'collected_at': datetime.now(timezone.utc).isoformat()
                    },
                    'configmaps': cms_data
                }

                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(output_data, f, indent=2, ensure_ascii=False)

                collected_files.append(output_file)
                logger.info(f"ConfigMaps: {len(cms_data)} coletados")

        except ApiException as e:
            raise CollectionError(f"Erro ao coletar ConfigMaps: {e}")

        return collected_files

    def _collect_secrets_metadata(self, **kwargs) -> list[str]:
        """
        Coleta APENAS metadados de Secrets (sem valores sensíveis).

        IMPORTANTE: Por segurança, os valores dos secrets NÃO são coletados,
        apenas informações sobre sua existência e estrutura.
        """
        collected_files = []

        logger.info("Coletando Secrets Metadata", namespace=self.namespace)

        try:
            secrets = self._core_v1.list_namespaced_secret(self.namespace)

            secrets_data = []
            for secret in secrets.items:
                secrets_data.append({
                    'name': secret.metadata.name,
                    'namespace': secret.metadata.namespace,
                    'type': secret.type,
                    'creation_timestamp': secret.metadata.creation_timestamp.isoformat() if secret.metadata.creation_timestamp else None,
                    'labels': dict(secret.metadata.labels) if secret.metadata.labels else {},
                    'annotations': dict(secret.metadata.annotations) if secret.metadata.annotations else {},
                    'data_keys': list(secret.data.keys()) if secret.data else [],
                    # NÃO incluir os valores dos secrets!
                    '_note': 'Valores dos secrets omitidos por segurança'
                })

            if secrets_data:
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                output_file = os.path.join(
                    self.config.output_dir,
                    f"k8s_secrets_metadata_{self.namespace}_{timestamp}.json"
                )

                output_data = {
                    '_metadata': {
                        'source': 'secrets_metadata',
                        'namespace': self.namespace,
                        'secret_count': len(secrets_data),
                        'collected_at': datetime.now(timezone.utc).isoformat(),
                        '_security_note': 'Valores dos secrets NÃO foram coletados por segurança'
                    },
                    'secrets': secrets_data
                }

                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(output_data, f, indent=2, ensure_ascii=False)

                collected_files.append(output_file)
                logger.info(f"Secrets Metadata: {len(secrets_data)} coletados (sem valores)")

        except ApiException as e:
            raise CollectionError(f"Erro ao coletar Secrets Metadata: {e}")

        return collected_files

    def _collect_network_policies(self, **kwargs) -> list[str]:
        """Coleta Network Policies do namespace."""
        collected_files = []

        logger.info("Coletando Network Policies", namespace=self.namespace)

        try:
            netpols = self._networking_v1.list_namespaced_network_policy(self.namespace)

            netpols_data = []
            for np in netpols.items:
                netpols_data.append({
                    'name': np.metadata.name,
                    'namespace': np.metadata.namespace,
                    'creation_timestamp': np.metadata.creation_timestamp.isoformat() if np.metadata.creation_timestamp else None,
                    'labels': dict(np.metadata.labels) if np.metadata.labels else {},
                    'pod_selector': np.spec.pod_selector.match_labels if np.spec.pod_selector else {},
                    'policy_types': list(np.spec.policy_types) if np.spec.policy_types else [],
                    'ingress_rules_count': len(np.spec.ingress) if np.spec.ingress else 0,
                    'egress_rules_count': len(np.spec.egress) if np.spec.egress else 0
                })

            if netpols_data:
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                output_file = os.path.join(
                    self.config.output_dir,
                    f"k8s_network_policies_{self.namespace}_{timestamp}.json"
                )

                output_data = {
                    '_metadata': {
                        'source': 'network_policies',
                        'namespace': self.namespace,
                        'policy_count': len(netpols_data),
                        'collected_at': datetime.now(timezone.utc).isoformat()
                    },
                    'network_policies': netpols_data
                }

                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(output_data, f, indent=2, ensure_ascii=False)

                collected_files.append(output_file)
                logger.info(f"Network Policies: {len(netpols_data)} coletadas")
            else:
                logger.info("Network Policies: nenhuma política encontrada")

        except ApiException as e:
            raise CollectionError(f"Erro ao coletar Network Policies: {e}")

        return collected_files

    def _collect_all(self, **kwargs) -> list[str]:
        """Coleta todas as fontes disponíveis."""
        collected_files = []

        # Pod Logs
        try:
            collected_files.extend(self._collect_pod_logs(**kwargs))
        except Exception as e:
            logger.warning(f"Falha ao coletar Pod Logs: {e}")

        # Events
        try:
            collected_files.extend(self._collect_events(**kwargs))
        except Exception as e:
            logger.warning(f"Falha ao coletar Events: {e}")

        # Resources
        try:
            collected_files.extend(self._collect_resources(**kwargs))
        except Exception as e:
            logger.warning(f"Falha ao coletar Resources: {e}")

        # ConfigMaps
        try:
            collected_files.extend(self._collect_configmaps(**kwargs))
        except Exception as e:
            logger.warning(f"Falha ao coletar ConfigMaps: {e}")

        # Secrets Metadata
        try:
            collected_files.extend(self._collect_secrets_metadata(**kwargs))
        except Exception as e:
            logger.warning(f"Falha ao coletar Secrets Metadata: {e}")

        # Network Policies
        try:
            collected_files.extend(self._collect_network_policies(**kwargs))
        except Exception as e:
            logger.warning(f"Falha ao coletar Network Policies: {e}")

        return collected_files

    # =========================================================================
    # Métodos auxiliares de serialização
    # =========================================================================

    def _serialize_pod(self, pod) -> dict:
        """Serializa um Pod para dicionário."""
        return {
            'name': pod.metadata.name,
            'namespace': pod.metadata.namespace,
            'uid': pod.metadata.uid,
            'creation_timestamp': pod.metadata.creation_timestamp.isoformat() if pod.metadata.creation_timestamp else None,
            'labels': dict(pod.metadata.labels) if pod.metadata.labels else {},
            'annotations': dict(pod.metadata.annotations) if pod.metadata.annotations else {},
            'status': {
                'phase': pod.status.phase,
                'pod_ip': pod.status.pod_ip,
                'host_ip': pod.status.host_ip,
                'start_time': pod.status.start_time.isoformat() if pod.status.start_time else None,
                'conditions': [
                    {'type': c.type, 'status': c.status, 'reason': c.reason}
                    for c in (pod.status.conditions or [])
                ]
            },
            'spec': {
                'node_name': pod.spec.node_name,
                'service_account': pod.spec.service_account_name,
                'restart_policy': pod.spec.restart_policy,
                'containers': [
                    {
                        'name': c.name,
                        'image': c.image,
                        'ports': [{'containerPort': p.container_port, 'protocol': p.protocol} for p in (c.ports or [])]
                    }
                    for c in (pod.spec.containers or [])
                ]
            }
        }

    def _serialize_deployment(self, deployment) -> dict:
        """Serializa um Deployment para dicionário."""
        return {
            'name': deployment.metadata.name,
            'namespace': deployment.metadata.namespace,
            'uid': deployment.metadata.uid,
            'creation_timestamp': deployment.metadata.creation_timestamp.isoformat() if deployment.metadata.creation_timestamp else None,
            'labels': dict(deployment.metadata.labels) if deployment.metadata.labels else {},
            'spec': {
                'replicas': deployment.spec.replicas,
                'selector': deployment.spec.selector.match_labels if deployment.spec.selector else {}
            },
            'status': {
                'replicas': deployment.status.replicas,
                'ready_replicas': deployment.status.ready_replicas,
                'available_replicas': deployment.status.available_replicas,
                'updated_replicas': deployment.status.updated_replicas
            }
        }

    def _serialize_service(self, service) -> dict:
        """Serializa um Service para dicionário."""
        return {
            'name': service.metadata.name,
            'namespace': service.metadata.namespace,
            'uid': service.metadata.uid,
            'creation_timestamp': service.metadata.creation_timestamp.isoformat() if service.metadata.creation_timestamp else None,
            'labels': dict(service.metadata.labels) if service.metadata.labels else {},
            'spec': {
                'type': service.spec.type,
                'cluster_ip': service.spec.cluster_ip,
                'external_ips': service.spec.external_i_ps,
                'ports': [
                    {'name': p.name, 'port': p.port, 'target_port': str(p.target_port), 'protocol': p.protocol}
                    for p in (service.spec.ports or [])
                ],
                'selector': dict(service.spec.selector) if service.spec.selector else {}
            }
        }

    def _serialize_replicaset(self, rs) -> dict:
        """Serializa um ReplicaSet para dicionário."""
        return {
            'name': rs.metadata.name,
            'namespace': rs.metadata.namespace,
            'uid': rs.metadata.uid,
            'creation_timestamp': rs.metadata.creation_timestamp.isoformat() if rs.metadata.creation_timestamp else None,
            'owner_references': [
                {'kind': o.kind, 'name': o.name}
                for o in (rs.metadata.owner_references or [])
            ],
            'spec': {
                'replicas': rs.spec.replicas
            },
            'status': {
                'replicas': rs.status.replicas,
                'ready_replicas': rs.status.ready_replicas
            }
        }

    def _serialize_daemonset(self, ds) -> dict:
        """Serializa um DaemonSet para dicionário."""
        return {
            'name': ds.metadata.name,
            'namespace': ds.metadata.namespace,
            'uid': ds.metadata.uid,
            'creation_timestamp': ds.metadata.creation_timestamp.isoformat() if ds.metadata.creation_timestamp else None,
            'labels': dict(ds.metadata.labels) if ds.metadata.labels else {},
            'status': {
                'current_number_scheduled': ds.status.current_number_scheduled,
                'desired_number_scheduled': ds.status.desired_number_scheduled,
                'number_ready': ds.status.number_ready
            }
        }

    def _serialize_statefulset(self, ss) -> dict:
        """Serializa um StatefulSet para dicionário."""
        return {
            'name': ss.metadata.name,
            'namespace': ss.metadata.namespace,
            'uid': ss.metadata.uid,
            'creation_timestamp': ss.metadata.creation_timestamp.isoformat() if ss.metadata.creation_timestamp else None,
            'labels': dict(ss.metadata.labels) if ss.metadata.labels else {},
            'spec': {
                'replicas': ss.spec.replicas,
                'service_name': ss.spec.service_name
            },
            'status': {
                'replicas': ss.status.replicas,
                'ready_replicas': ss.status.ready_replicas,
                'current_replicas': ss.status.current_replicas
            }
        }

    def _get_original_path(self, local_path: str, source_type: str) -> str:
        """Retorna o caminho original da evidência no Kubernetes."""
        return f"k8s://{self.namespace}/{source_type}"

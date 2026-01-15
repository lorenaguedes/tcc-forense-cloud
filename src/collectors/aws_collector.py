
import gzip
import json
import os
from datetime import datetime, timezone, timedelta
from typing import Optional, List

import structlog

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

from .base import (
    AuthenticationError,
    BaseCollector,
    CollectionConfig,
    CollectionError,
)

logger = structlog.get_logger(__name__)


class AWSCollector(BaseCollector):

    SOURCES = [
        'cloudtrail',
        'cloudwatch_logs',
        's3_access_logs',
        'ec2_metadata',
        'vpc_flow_logs',
        'all'
    ]

    def __init__(
        self,
        config: CollectionConfig,
        region: str = "us-east-1",
        profile: Optional[str] = None,
        access_key_id: Optional[str] = None,
        secret_access_key: Optional[str] = None
    ):
        """
        Inicializa o coletor AWS.

        Args:
            config: Configuração da coleta
            region: Região AWS (ex: us-east-1, sa-east-1)
            profile: Nome do perfil AWS (~/.aws/credentials)
            access_key_id: Access Key (alternativa ao profile)
            secret_access_key: Secret Key (alternativa ao profile)
        """
        if not AWS_AVAILABLE:
            raise ImportError(
                "SDK AWS (boto3) não instalado. Execute: pip install boto3"
            )

        super().__init__(config)

        self.region = region
        self.profile = profile
        self._access_key_id = access_key_id
        self._secret_access_key = secret_access_key

        # Clientes boto3 (inicializados na autenticação)
        self._session: Optional[boto3.Session] = None
        self._cloudtrail = None
        self._cloudwatch_logs = None
        self._s3 = None
        self._ec2 = None

        self._account_id: Optional[str] = None

    @property
    def provider_name(self) -> str:
        return "aws"

    @property
    def supported_sources(self) -> list[str]:
        return self.SOURCES

    def _authenticate(self) -> bool:
        """Autentica com a AWS usando credenciais configuradas."""
        try:
            # Criar sessão boto3
            session_kwargs = {"region_name": self.region}

            if self.profile:
                session_kwargs["profile_name"] = self.profile
            elif self._access_key_id and self._secret_access_key:
                session_kwargs["aws_access_key_id"] = self._access_key_id
                session_kwargs["aws_secret_access_key"] = self._secret_access_key

            self._session = boto3.Session(**session_kwargs)

            # Verificar credenciais obtendo Account ID
            sts = self._session.client('sts')
            identity = sts.get_caller_identity()
            self._account_id = identity['Account']

            # Inicializar clientes
            self._cloudtrail = self._session.client('cloudtrail')
            self._cloudwatch_logs = self._session.client('logs')
            self._s3 = self._session.client('s3')
            self._ec2 = self._session.client('ec2')

            logger.info(
                "Autenticado na AWS",
                account_id=self._account_id,
                region=self.region,
                user_arn=identity.get('Arn')
            )
            return True

        except NoCredentialsError:
            raise AuthenticationError(
                "Credenciais AWS não encontradas. Execute 'aws configure' ou "
                "forneça access_key_id e secret_access_key."
            )
        except ProfileNotFound as e:
            raise AuthenticationError(f"Perfil AWS não encontrado: {e}")
        except ClientError as e:
            raise AuthenticationError(f"Erro de autenticação AWS: {e}")

    def _get_source_metadata(self, source_type: str) -> dict:
        """Retorna metadados da fonte AWS."""
        return {
            "region": self.region,
            "account_id": self._account_id or "unknown",
            "profile": self.profile or "default"
        }

    def _collect_source(self, source_type: str, **kwargs) -> list[str]:
        """Roteia a coleta para o método apropriado."""
        collectors = {
            'cloudtrail': self._collect_cloudtrail,
            'cloudwatch_logs': self._collect_cloudwatch_logs,
            's3_access_logs': self._collect_s3_access_logs,
            'ec2_metadata': self._collect_ec2_metadata,
            'vpc_flow_logs': self._collect_vpc_flow_logs,
            'all': self._collect_all
        }
        return collectors[source_type](**kwargs)

    def _collect_cloudtrail(
        self,
        trail_name: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        max_events: int = 1000,
        **kwargs
    ) -> list[str]:
        """
        Coleta eventos do AWS CloudTrail.

        Args:
            trail_name: Nome do trail (opcional, usa lookup_events se não especificado)
            start_time: Início do período de coleta
            end_time: Fim do período de coleta
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
            "Coletando CloudTrail",
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            max_events=max_events
        )

        try:
            events = []
            paginator = self._cloudtrail.get_paginator('lookup_events')

            page_iterator = paginator.paginate(
                StartTime=start_time,
                EndTime=end_time,
                PaginationConfig={'MaxItems': max_events}
            )

            for page in page_iterator:
                for event in page.get('Events', []):
                    # Parsear CloudTrailEvent (é uma string JSON)
                    event_data = {
                        'EventId': event.get('EventId'),
                        'EventName': event.get('EventName'),
                        'EventTime': event.get('EventTime').isoformat() if event.get('EventTime') else None,
                        'EventSource': event.get('EventSource'),
                        'Username': event.get('Username'),
                        'Resources': event.get('Resources', []),
                    }

                    # Incluir detalhes completos se disponíveis
                    if 'CloudTrailEvent' in event:
                        try:
                            event_data['CloudTrailEvent'] = json.loads(event['CloudTrailEvent'])
                        except json.JSONDecodeError:
                            event_data['CloudTrailEvent'] = event['CloudTrailEvent']

                    events.append(event_data)

            if events:
                # Salvar eventos em arquivo JSON
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                output_file = os.path.join(
                    self.config.output_dir,
                    f"aws_cloudtrail_{self.region}_{timestamp}.json"
                )

                output_data = {
                    '_metadata': {
                        'source': 'cloudtrail',
                        'region': self.region,
                        'account_id': self._account_id,
                        'start_time': start_time.isoformat(),
                        'end_time': end_time.isoformat(),
                        'event_count': len(events),
                        'collected_at': datetime.now(timezone.utc).isoformat()
                    },
                    'events': events
                }

                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(output_data, f, indent=2, ensure_ascii=False, default=str)

                collected_files.append(output_file)
                logger.info(f"CloudTrail: {len(events)} eventos coletados")
            else:
                logger.warning("CloudTrail: nenhum evento encontrado no período")

        except ClientError as e:
            raise CollectionError(f"Erro ao coletar CloudTrail: {e}")

        return collected_files

    def _collect_cloudwatch_logs(
        self,
        log_group_name: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        filter_pattern: str = "",
        max_events: int = 10000,
        **kwargs
    ) -> list[str]:
        """
        Coleta logs do CloudWatch Logs.

        Args:
            log_group_name: Nome do Log Group (ex: /aws/lambda/my-function)
            start_time: Início do período
            end_time: Fim do período
            filter_pattern: Padrão de filtro CloudWatch
            max_events: Número máximo de eventos

        Returns:
            Lista de caminhos dos arquivos coletados
        """
        collected_files = []

        # Definir período padrão
        if end_time is None:
            end_time = datetime.now(timezone.utc)
        if start_time is None:
            start_time = end_time - timedelta(hours=24)

        # Converter para timestamp em milissegundos
        start_ms = int(start_time.timestamp() * 1000)
        end_ms = int(end_time.timestamp() * 1000)

        logger.info(
            "Coletando CloudWatch Logs",
            log_group=log_group_name,
            start_time=start_time.isoformat()
        )

        try:
            events = []

            paginator = self._cloudwatch_logs.get_paginator('filter_log_events')
            page_iterator = paginator.paginate(
                logGroupName=log_group_name,
                startTime=start_ms,
                endTime=end_ms,
                filterPattern=filter_pattern,
                PaginationConfig={'MaxItems': max_events}
            )

            for page in page_iterator:
                for event in page.get('events', []):
                    events.append({
                        'timestamp': datetime.fromtimestamp(
                            event['timestamp'] / 1000, tz=timezone.utc
                        ).isoformat(),
                        'message': event.get('message'),
                        'logStreamName': event.get('logStreamName'),
                        'eventId': event.get('eventId'),
                        'ingestionTime': event.get('ingestionTime')
                    })

            if events:
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                safe_name = log_group_name.replace('/', '_').strip('_')
                output_file = os.path.join(
                    self.config.output_dir,
                    f"aws_cloudwatch_{safe_name}_{timestamp}.json"
                )

                output_data = {
                    '_metadata': {
                        'source': 'cloudwatch_logs',
                        'log_group': log_group_name,
                        'region': self.region,
                        'account_id': self._account_id,
                        'start_time': start_time.isoformat(),
                        'end_time': end_time.isoformat(),
                        'filter_pattern': filter_pattern,
                        'event_count': len(events),
                        'collected_at': datetime.now(timezone.utc).isoformat()
                    },
                    'events': events
                }

                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(output_data, f, indent=2, ensure_ascii=False)

                collected_files.append(output_file)
                logger.info(f"CloudWatch Logs: {len(events)} eventos coletados")
            else:
                logger.warning("CloudWatch Logs: nenhum evento encontrado")

        except ClientError as e:
            if 'ResourceNotFoundException' in str(e):
                raise CollectionError(f"Log Group não encontrado: {log_group_name}")
            raise CollectionError(f"Erro ao coletar CloudWatch Logs: {e}")

        return collected_files

    def _collect_s3_access_logs(
        self,
        bucket_name: str,
        prefix: str = "",
        max_files: int = 100,
        **kwargs
    ) -> list[str]:
        """
        Coleta logs de acesso S3 de um bucket.

        Args:
            bucket_name: Nome do bucket que contém os logs
            prefix: Prefixo para filtrar objetos
            max_files: Número máximo de arquivos a baixar

        Returns:
            Lista de caminhos dos arquivos coletados
        """
        collected_files = []

        logger.info(
            "Coletando S3 Access Logs",
            bucket=bucket_name,
            prefix=prefix
        )

        try:
            # Listar objetos no bucket
            paginator = self._s3.get_paginator('list_objects_v2')

            list_kwargs = {'Bucket': bucket_name}
            if prefix:
                list_kwargs['Prefix'] = prefix

            files_downloaded = 0
            all_logs = []

            for page in paginator.paginate(**list_kwargs):
                for obj in page.get('Contents', []):
                    if files_downloaded >= max_files:
                        break

                    key = obj['Key']

                    # Baixar o arquivo
                    response = self._s3.get_object(Bucket=bucket_name, Key=key)
                    content = response['Body'].read()

                    # Descomprimir se necessário
                    if key.endswith('.gz'):
                        content = gzip.decompress(content)

                    # Decodificar e adicionar aos logs
                    try:
                        log_content = content.decode('utf-8')
                        all_logs.append({
                            'key': key,
                            'last_modified': obj['LastModified'].isoformat(),
                            'size': obj['Size'],
                            'content': log_content
                        })
                    except UnicodeDecodeError:
                        logger.warning(f"Não foi possível decodificar: {key}")

                    files_downloaded += 1

            if all_logs:
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                output_file = os.path.join(
                    self.config.output_dir,
                    f"aws_s3_logs_{bucket_name}_{timestamp}.json"
                )

                output_data = {
                    '_metadata': {
                        'source': 's3_access_logs',
                        'bucket': bucket_name,
                        'prefix': prefix,
                        'region': self.region,
                        'files_count': len(all_logs),
                        'collected_at': datetime.now(timezone.utc).isoformat()
                    },
                    'logs': all_logs
                }

                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(output_data, f, indent=2, ensure_ascii=False)

                collected_files.append(output_file)
                logger.info(f"S3 Access Logs: {len(all_logs)} arquivos coletados")
            else:
                logger.warning("S3 Access Logs: nenhum arquivo encontrado")

        except ClientError as e:
            if 'NoSuchBucket' in str(e):
                raise CollectionError(f"Bucket não encontrado: {bucket_name}")
            raise CollectionError(f"Erro ao coletar S3 Access Logs: {e}")

        return collected_files

    def _collect_ec2_metadata(
        self,
        instance_ids: Optional[List[str]] = None,
        **kwargs
    ) -> list[str]:
        """
        Coleta metadados de instâncias EC2.

        Args:
            instance_ids: Lista de IDs de instâncias (None = todas)

        Returns:
            Lista de caminhos dos arquivos coletados
        """
        collected_files = []

        logger.info(
            "Coletando EC2 Metadata",
            instance_ids=instance_ids or "all"
        )

        try:
            # Descrever instâncias
            describe_kwargs = {}
            if instance_ids:
                describe_kwargs['InstanceIds'] = instance_ids

            response = self._ec2.describe_instances(**describe_kwargs)

            instances = []
            for reservation in response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_data = {
                        'InstanceId': instance.get('InstanceId'),
                        'InstanceType': instance.get('InstanceType'),
                        'State': instance.get('State', {}).get('Name'),
                        'LaunchTime': instance.get('LaunchTime').isoformat() if instance.get('LaunchTime') else None,
                        'PrivateIpAddress': instance.get('PrivateIpAddress'),
                        'PublicIpAddress': instance.get('PublicIpAddress'),
                        'VpcId': instance.get('VpcId'),
                        'SubnetId': instance.get('SubnetId'),
                        'SecurityGroups': instance.get('SecurityGroups', []),
                        'Tags': instance.get('Tags', []),
                        'IamInstanceProfile': instance.get('IamInstanceProfile'),
                        'Architecture': instance.get('Architecture'),
                        'RootDeviceType': instance.get('RootDeviceType'),
                        'BlockDeviceMappings': [
                            {
                                'DeviceName': bdm.get('DeviceName'),
                                'VolumeId': bdm.get('Ebs', {}).get('VolumeId'),
                                'Status': bdm.get('Ebs', {}).get('Status'),
                                'AttachTime': bdm.get('Ebs', {}).get('AttachTime').isoformat()
                                    if bdm.get('Ebs', {}).get('AttachTime') else None
                            }
                            for bdm in instance.get('BlockDeviceMappings', [])
                        ],
                        'NetworkInterfaces': [
                            {
                                'NetworkInterfaceId': ni.get('NetworkInterfaceId'),
                                'PrivateIpAddress': ni.get('PrivateIpAddress'),
                                'MacAddress': ni.get('MacAddress'),
                                'Status': ni.get('Status')
                            }
                            for ni in instance.get('NetworkInterfaces', [])
                        ]
                    }
                    instances.append(instance_data)

            if instances:
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                output_file = os.path.join(
                    self.config.output_dir,
                    f"aws_ec2_metadata_{self.region}_{timestamp}.json"
                )

                output_data = {
                    '_metadata': {
                        'source': 'ec2_metadata',
                        'region': self.region,
                        'account_id': self._account_id,
                        'instance_count': len(instances),
                        'collected_at': datetime.now(timezone.utc).isoformat()
                    },
                    'instances': instances
                }

                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(output_data, f, indent=2, ensure_ascii=False)

                collected_files.append(output_file)
                logger.info(f"EC2 Metadata: {len(instances)} instâncias coletadas")
            else:
                logger.warning("EC2 Metadata: nenhuma instância encontrada")

        except ClientError as e:
            raise CollectionError(f"Erro ao coletar EC2 Metadata: {e}")

        return collected_files

    def _collect_vpc_flow_logs(
        self,
        log_group_name: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        max_events: int = 10000,
        **kwargs
    ) -> list[str]:
        """
        Coleta VPC Flow Logs do CloudWatch Logs.

        Args:
            log_group_name: Nome do Log Group dos Flow Logs
            start_time: Início do período
            end_time: Fim do período
            max_events: Número máximo de eventos

        Returns:
            Lista de caminhos dos arquivos coletados
        """
        # VPC Flow Logs são armazenados no CloudWatch Logs
        # Reutilizamos o método de coleta com parsing específico

        collected_files = self._collect_cloudwatch_logs(
            log_group_name=log_group_name,
            start_time=start_time,
            end_time=end_time,
            max_events=max_events,
            **kwargs
        )

        # Renomear arquivos para indicar que são VPC Flow Logs
        renamed_files = []
        for file_path in collected_files:
            new_path = file_path.replace('cloudwatch', 'vpc_flow_logs')
            if file_path != new_path:
                os.rename(file_path, new_path)
                renamed_files.append(new_path)
            else:
                renamed_files.append(file_path)

        return renamed_files

    def _collect_all(self, **kwargs) -> list[str]:
        """
        Coleta todas as fontes disponíveis.

        Tenta coletar de cada fonte, registrando warnings para falhas.
        """
        collected_files = []

        # CloudTrail (sempre disponível)
        try:
            collected_files.extend(self._collect_cloudtrail(**kwargs))
        except Exception as e:
            logger.warning(f"Falha ao coletar CloudTrail: {e}")

        # EC2 Metadata
        try:
            collected_files.extend(self._collect_ec2_metadata(**kwargs))
        except Exception as e:
            logger.warning(f"Falha ao coletar EC2 Metadata: {e}")

        # CloudWatch Logs (requer log_group_name)
        if 'log_group_name' in kwargs:
            try:
                collected_files.extend(self._collect_cloudwatch_logs(**kwargs))
            except Exception as e:
                logger.warning(f"Falha ao coletar CloudWatch Logs: {e}")

        # S3 Access Logs (requer bucket_name)
        if 'bucket_name' in kwargs:
            try:
                collected_files.extend(self._collect_s3_access_logs(**kwargs))
            except Exception as e:
                logger.warning(f"Falha ao coletar S3 Access Logs: {e}")

        return collected_files

    def _get_original_path(self, local_path: str, source_type: str) -> str:
        """Retorna o caminho original da evidência na AWS."""
        return f"aws://{self._account_id}/{self.region}/{source_type}"

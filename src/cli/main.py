"""
CLI - Interface de Linha de Comando
===================================

Uso:
    python -m src.cli.main --help
    python -m src.cli.main hash arquivo.txt
    python -m src.cli.main collect docker --case-id CASO-001
    python -m src.cli.main collect aws --case-id CASO-001 --source cloudtrail

Autor: [Seu Nome]
"""

import os
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from src.core import ForensicHasher, ManifestGenerator
from src.collectors import (
    CollectionConfig,
    DockerCollector,
    AWSCollector,
    AzureCollector,
    GCPCollector,
    KubernetesCollector,
    check_collector_availability
)

console = Console()
VERSION = "1.0.0"


def _print_collection_result(result):
    """Imprime o resultado da coleta em formato de tabela."""
    table = Table(title="Resultado da Coleta")
    table.add_column("Campo", style="cyan")
    table.add_column("Valor")
    
    table.add_row("Status", "[green]OK[/green]" if result.success else "[red]FALHA[/red]")
    table.add_row("Collection ID", result.collection_id)
    table.add_row("Evidências", str(result.evidence_count))
    table.add_row("Tamanho", f"{result.total_size_bytes / 1024:.2f} KB")
    table.add_row("Duração", f"{result.duration_seconds:.2f}s")
    table.add_row("Manifesto", result.manifest_path or "N/A")
    
    if result.errors:
        table.add_row("Erros", "[red]" + "; ".join(result.errors) + "[/red]")
    if result.warnings:
        table.add_row("Avisos", "[yellow]" + "; ".join(result.warnings[:3]) + "[/yellow]")
    
    console.print(table)


@click.group()
@click.version_option(version=VERSION)
def cli():
    """Framework de Perícia Digital em Nuvem."""
    pass


# =============================================================================
# Comando: hash
# =============================================================================
@cli.command('hash')
@click.argument('file_path')
@click.option('--algorithm', '-a', default='sha256',
              type=click.Choice(['sha256', 'sha512', 'sha3_256']),
              help='Algoritmo de hash')
def hash_file(file_path, algorithm):
    """Calcula o hash de um arquivo."""
    try:
        hasher = ForensicHasher(algorithm=algorithm)
        result = hasher.hash_file(file_path)
        
        console.print(f"\n[bold]Arquivo:[/bold] {result.file_path}")
        console.print(f"[bold]Algoritmo:[/bold] {result.algorithm}")
        console.print(f"[bold]Hash:[/bold] {result.hash_value}")
        console.print(f"[bold]Tamanho:[/bold] {result.file_size} bytes")
        console.print(f"[bold]Calculado em:[/bold] {result.calculated_at}")
        
    except Exception as e:
        console.print(f"[red]Erro: {e}[/red]")
        sys.exit(1)


# =============================================================================
# Comando: verify
# =============================================================================
@cli.command('verify')
@click.option('--manifest', '-m', required=True, help='Caminho do manifesto JSON')
def verify_integrity(manifest):
    """Verifica a integridade das evidências usando o manifesto."""
    
    console.print(f"\n[bold blue]Verificando integridade...[/bold blue]")
    
    try:
        generator = ManifestGenerator.load(manifest)
        hasher = ForensicHasher(algorithm='sha256')
        
        table = Table(title="Verificação de Integridade")
        table.add_column("Arquivo", style="cyan")
        table.add_column("Status")
        table.add_column("Hash (16 chars)")
        
        all_valid = True
        
        for evidence in generator.manifest.evidence_items:
            if evidence.local_path == "[in-memory]":
                table.add_row(evidence.filename, "[yellow]SKIP[/yellow]", "N/A")
                continue
            
            if not os.path.exists(evidence.local_path):
                table.add_row(evidence.filename, "[red]NOT FOUND[/red]", evidence.sha256[:16])
                all_valid = False
                continue
            
            is_valid = hasher.verify_file(evidence.local_path, evidence.sha256)
            
            if is_valid:
                table.add_row(evidence.filename, "[green]OK[/green]", evidence.sha256[:16])
            else:
                table.add_row(evidence.filename, "[red]FAIL[/red]", evidence.sha256[:16])
                all_valid = False
        
        console.print(table)
        
        if all_valid:
            console.print("\n[bold green]✓ Todas as evidências íntegras![/bold green]")
        else:
            console.print("\n[bold red]✗ Algumas evidências falharam![/bold red]")
            sys.exit(1)
            
    except Exception as e:
        console.print(f"[red]Erro: {e}[/red]")
        sys.exit(1)


# =============================================================================
# Grupo: collect
# =============================================================================
@cli.group()
def collect():
    """Comandos de coleta de evidências."""
    pass


# -----------------------------------------------------------------------------
# Coletor Docker
# -----------------------------------------------------------------------------
@collect.command('docker')
@click.option('--source', '-s', default='all_containers',
              type=click.Choice(['container_logs', 'container_inspect', 'image_info', 'network_info', 'all_containers']))
@click.option('--container-id', '-c', default=None, help='ID do container')
@click.option('--output', '-o', default='./output', help='Diretório de saída')
@click.option('--case-id', required=True, help='ID do caso')
@click.option('--agent-name', default=None, help='Nome do agente')
@click.option('--dry-run', is_flag=True, help='Simular sem coletar')
def collect_docker(source, container_id, output, case_id, agent_name, dry_run):
    """Coleta evidências de Docker."""
    
    if DockerCollector is None:
        console.print("[red]Erro: docker SDK não instalado. Execute: pip install docker[/red]")
        sys.exit(1)
    
    if source in ['container_logs', 'container_inspect'] and not container_id:
        console.print("[red]Erro: --container-id obrigatório para esta fonte[/red]")
        sys.exit(1)
    
    agent_name = agent_name or os.getenv('USERNAME', os.getenv('USER', 'unknown'))
    
    config = CollectionConfig(
        case_id=case_id,
        agent_name=agent_name,
        agent_id="CLI",
        output_dir=output,
        dry_run=dry_run
    )
    
    console.print(f"\n[bold blue]Coletando {source}...[/bold blue]")
    console.print(f"Case ID: {case_id}")
    console.print(f"Output: {output}\n")
    
    try:
        collector = DockerCollector(config)
        
        kwargs = {}
        if container_id:
            kwargs['container_id'] = container_id
        
        result = collector.collect(source, **kwargs)
        _print_collection_result(result)
        
    except Exception as e:
        console.print(f"[red]Erro: {e}[/red]")
        sys.exit(1)


# -----------------------------------------------------------------------------
# Coletor AWS
# -----------------------------------------------------------------------------
@collect.command('aws')
@click.option('--source', '-s', default='cloudtrail',
              type=click.Choice(['cloudtrail', 'cloudwatch_logs', 's3_access_logs', 'ec2_metadata', 'vpc_flow_logs', 'all']))
@click.option('--region', '-r', default='us-east-1', help='Região AWS')
@click.option('--profile', '-p', default=None, help='Perfil AWS')
@click.option('--output', '-o', default='./output', help='Diretório de saída')
@click.option('--case-id', required=True, help='ID do caso')
@click.option('--agent-name', default=None, help='Nome do agente')
@click.option('--log-group', default=None, help='Nome do Log Group (para cloudwatch_logs)')
@click.option('--bucket', default=None, help='Nome do bucket (para s3_access_logs)')
@click.option('--max-events', default=1000, help='Número máximo de eventos')
@click.option('--dry-run', is_flag=True, help='Simular sem coletar')
def collect_aws(source, region, profile, output, case_id, agent_name, log_group, bucket, max_events, dry_run):
    """Coleta evidências da AWS."""
    
    if AWSCollector is None:
        console.print("[red]Erro: boto3 não instalado. Execute: pip install boto3[/red]")
        sys.exit(1)
    
    if source == 'cloudwatch_logs' and not log_group:
        console.print("[red]Erro: --log-group obrigatório para cloudwatch_logs[/red]")
        sys.exit(1)
    
    if source == 's3_access_logs' and not bucket:
        console.print("[red]Erro: --bucket obrigatório para s3_access_logs[/red]")
        sys.exit(1)
    
    agent_name = agent_name or os.getenv('USERNAME', os.getenv('USER', 'unknown'))
    
    config = CollectionConfig(
        case_id=case_id,
        agent_name=agent_name,
        agent_id="CLI",
        output_dir=output,
        dry_run=dry_run
    )
    
    console.print(f"\n[bold blue]Coletando AWS {source}...[/bold blue]")
    console.print(f"Case ID: {case_id}")
    console.print(f"Region: {region}")
    console.print(f"Output: {output}\n")
    
    try:
        collector = AWSCollector(config, region=region, profile=profile)
        
        kwargs = {'max_events': max_events}
        if log_group:
            kwargs['log_group_name'] = log_group
        if bucket:
            kwargs['bucket_name'] = bucket
        
        result = collector.collect(source, **kwargs)
        _print_collection_result(result)
        
    except Exception as e:
        console.print(f"[red]Erro: {e}[/red]")
        sys.exit(1)


# -----------------------------------------------------------------------------
# Coletor Azure
# -----------------------------------------------------------------------------
@collect.command('azure')
@click.option('--source', '-s', default='activity_log',
              type=click.Choice(['activity_log', 'blob_storage', 'vm_metadata', 'nsg_flow_logs', 'all']))
@click.option('--subscription-id', required=True, help='ID da assinatura Azure')
@click.option('--resource-group', '-g', default=None, help='Resource Group')
@click.option('--output', '-o', default='./output', help='Diretório de saída')
@click.option('--case-id', required=True, help='ID do caso')
@click.option('--agent-name', default=None, help='Nome do agente')
@click.option('--account-url', default=None, help='URL da conta de storage')
@click.option('--container', default=None, help='Nome do container')
@click.option('--dry-run', is_flag=True, help='Simular sem coletar')
def collect_azure(source, subscription_id, resource_group, output, case_id, agent_name, account_url, container, dry_run):
    """Coleta evidências do Azure."""
    
    if AzureCollector is None:
        console.print("[red]Erro: SDKs Azure não instalados.[/red]")
        console.print("[yellow]Execute: pip install azure-identity azure-mgmt-monitor azure-mgmt-compute azure-storage-blob[/yellow]")
        sys.exit(1)
    
    if source == 'blob_storage' and (not account_url or not container):
        console.print("[red]Erro: --account-url e --container obrigatórios para blob_storage[/red]")
        sys.exit(1)
    
    agent_name = agent_name or os.getenv('USERNAME', os.getenv('USER', 'unknown'))
    
    config = CollectionConfig(
        case_id=case_id,
        agent_name=agent_name,
        agent_id="CLI",
        output_dir=output,
        dry_run=dry_run
    )
    
    console.print(f"\n[bold blue]Coletando Azure {source}...[/bold blue]")
    console.print(f"Case ID: {case_id}")
    console.print(f"Subscription: {subscription_id[:8]}...")
    console.print(f"Output: {output}\n")
    
    try:
        collector = AzureCollector(config, subscription_id=subscription_id)
        
        kwargs = {}
        if resource_group:
            kwargs['resource_group'] = resource_group
        if account_url:
            kwargs['account_url'] = account_url
        if container:
            kwargs['container_name'] = container
        
        result = collector.collect(source, **kwargs)
        _print_collection_result(result)
        
    except Exception as e:
        console.print(f"[red]Erro: {e}[/red]")
        sys.exit(1)


# -----------------------------------------------------------------------------
# Coletor GCP
# -----------------------------------------------------------------------------
@collect.command('gcp')
@click.option('--source', '-s', default='cloud_logging',
              type=click.Choice(['cloud_logging', 'gcs_logs', 'compute_metadata', 'all']))
@click.option('--project-id', required=True, help='ID do projeto GCP')
@click.option('--output', '-o', default='./output', help='Diretório de saída')
@click.option('--case-id', required=True, help='ID do caso')
@click.option('--agent-name', default=None, help='Nome do agente')
@click.option('--log-filter', default='', help='Filtro de logs')
@click.option('--bucket', default=None, help='Nome do bucket')
@click.option('--zone', default=None, help='Zona GCP')
@click.option('--max-entries', default=1000, help='Número máximo de entradas')
@click.option('--dry-run', is_flag=True, help='Simular sem coletar')
def collect_gcp(source, project_id, output, case_id, agent_name, log_filter, bucket, zone, max_entries, dry_run):
    """Coleta evidências do GCP."""
    
    if GCPCollector is None:
        console.print("[red]Erro: SDKs GCP não instalados.[/red]")
        console.print("[yellow]Execute: pip install google-cloud-logging google-cloud-storage google-cloud-compute[/yellow]")
        sys.exit(1)
    
    if source == 'gcs_logs' and not bucket:
        console.print("[red]Erro: --bucket obrigatório para gcs_logs[/red]")
        sys.exit(1)
    
    agent_name = agent_name or os.getenv('USERNAME', os.getenv('USER', 'unknown'))
    
    config = CollectionConfig(
        case_id=case_id,
        agent_name=agent_name,
        agent_id="CLI",
        output_dir=output,
        dry_run=dry_run
    )
    
    console.print(f"\n[bold blue]Coletando GCP {source}...[/bold blue]")
    console.print(f"Case ID: {case_id}")
    console.print(f"Project: {project_id}")
    console.print(f"Output: {output}\n")
    
    try:
        collector = GCPCollector(config, project_id=project_id)
        
        kwargs = {'max_entries': max_entries}
        if log_filter:
            kwargs['log_filter'] = log_filter
        if bucket:
            kwargs['bucket_name'] = bucket
        if zone:
            kwargs['zone'] = zone
        
        result = collector.collect(source, **kwargs)
        _print_collection_result(result)
        
    except Exception as e:
        console.print(f"[red]Erro: {e}[/red]")
        sys.exit(1)


# -----------------------------------------------------------------------------
# Coletor Kubernetes
# -----------------------------------------------------------------------------
@collect.command('k8s')
@click.option('--source', '-s', default='all',
              type=click.Choice(['pod_logs', 'events', 'resources', 'configmaps', 'secrets_metadata', 'network_policies', 'all']))
@click.option('--namespace', '-n', default='default', help='Namespace Kubernetes')
@click.option('--context', default=None, help='Contexto do kubeconfig')
@click.option('--output', '-o', default='./output', help='Diretório de saída')
@click.option('--case-id', required=True, help='ID do caso')
@click.option('--agent-name', default=None, help='Nome do agente')
@click.option('--pod', default=None, help='Nome do pod específico')
@click.option('--tail-lines', default=10000, help='Número de linhas de log')
@click.option('--dry-run', is_flag=True, help='Simular sem coletar')
def collect_k8s(source, namespace, context, output, case_id, agent_name, pod, tail_lines, dry_run):
    """Coleta evidências do Kubernetes."""
    
    if KubernetesCollector is None:
        console.print("[red]Erro: SDK Kubernetes não instalado.[/red]")
        console.print("[yellow]Execute: pip install kubernetes[/yellow]")
        sys.exit(1)
    
    agent_name = agent_name or os.getenv('USERNAME', os.getenv('USER', 'unknown'))
    
    config = CollectionConfig(
        case_id=case_id,
        agent_name=agent_name,
        agent_id="CLI",
        output_dir=output,
        dry_run=dry_run
    )
    
    console.print(f"\n[bold blue]Coletando Kubernetes {source}...[/bold blue]")
    console.print(f"Case ID: {case_id}")
    console.print(f"Namespace: {namespace}")
    console.print(f"Output: {output}\n")
    
    try:
        collector = KubernetesCollector(config, namespace=namespace, context=context)
        
        kwargs = {'tail_lines': tail_lines}
        if pod:
            kwargs['pod_name'] = pod
        
        result = collector.collect(source, **kwargs)
        _print_collection_result(result)
        
    except Exception as e:
        console.print(f"[red]Erro: {e}[/red]")
        sys.exit(1)
@cli.command('info')
def info():
    """Mostra informações sobre o framework e coletores disponíveis."""
    
    console.print(f"\n[bold cyan]TCC Forense Cloud v{VERSION}[/bold cyan]\n")
    
    table = Table(title="Status dos Coletores")
    table.add_column("Coletor", style="cyan")
    table.add_column("Status")
    table.add_column("Fontes Suportadas")
    
    availability = check_collector_availability()
    
    # Docker
    if availability.get('docker'):
        table.add_row("Docker", "[green]Disponível[/green]", 
                      "container_logs, container_inspect, image_info, network_info, all_containers")
    else:
        table.add_row("Docker", "[yellow]SDK não instalado[/yellow]", "pip install docker")
    
    # AWS
    if availability.get('aws'):
        table.add_row("AWS", "[green]Disponível[/green]",
                      "cloudtrail, cloudwatch_logs, s3_access_logs, ec2_metadata, vpc_flow_logs")
    else:
        table.add_row("AWS", "[yellow]SDK não instalado[/yellow]", "pip install boto3")
    
    # Azure
    if availability.get('azure'):
        table.add_row("Azure", "[green]Disponível[/green]",
                      "activity_log, blob_storage, vm_metadata, nsg_flow_logs")
    else:
        table.add_row("Azure", "[yellow]SDK não instalado[/yellow]", "pip install azure-*")
    
    # GCP
    if availability.get('gcp'):
        table.add_row("GCP", "[green]Disponível[/green]",
                      "cloud_logging, gcs_logs, compute_metadata")
    else:
        table.add_row("GCP", "[yellow]SDK não instalado[/yellow]", "pip install google-cloud-*")
    
    # Kubernetes
    if availability.get('kubernetes'):
        table.add_row("Kubernetes", "[green]Disponível[/green]",
                      "pod_logs, events, resources, configmaps")
    else:
        table.add_row("Kubernetes", "[yellow]SDK não instalado[/yellow]", "pip install kubernetes")
    
    console.print(table)
    
    console.print("\n[bold]Módulos Core:[/bold]")
    console.print("  [green]✓[/green] Hasher (SHA-256/512)")
    console.print("  [green]✓[/green] Manifest Generator")
    console.print("  [green]✓[/green] Chain of Custody")
    
    console.print("\n[bold]Exemplos de uso:[/bold]")
    console.print("  python -m src.cli.main collect docker --case-id CASO-001 --source all_containers")
    console.print("  python -m src.cli.main collect aws --case-id CASO-001 --region us-east-1")
    console.print("  python -m src.cli.main verify --manifest ./output/manifest.json")
    console.print("")


if __name__ == '__main__':
    cli()

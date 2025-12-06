"""
CLI - Interface de Linha de Comando
===================================

Uso:
    python -m src.cli.main --help
    python -m src.cli.main hash arquivo.txt
    python -m src.cli.main collect docker --case-id CASO-001

Autor: [Seu Nome]
"""

import os
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

# Adiciona src ao path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.core import ForensicHasher, ManifestGenerator
from src.collectors import CollectionConfig, DockerCollector

console = Console()
VERSION = "1.0.0"


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
        console.print("[red]Erro: docker SDK não instalado[/red]")
        sys.exit(1)
    
    if source in ['container_logs', 'container_inspect'] and not container_id:
        console.print("[red]Erro: --container-id obrigatório[/red]")
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
        
        # Mostra resultado
        table = Table(title="Resultado da Coleta")
        table.add_column("Campo", style="cyan")
        table.add_column("Valor")
        
        table.add_row("Status", "[green]OK[/green]" if result.success else "[red]FALHA[/red]")
        table.add_row("Collection ID", result.collection_id)
        table.add_row("Evidências", str(result.evidence_count))
        table.add_row("Tamanho", f"{result.total_size_bytes / 1024:.2f} KB")
        table.add_row("Duração", f"{result.duration_seconds:.2f}s")
        table.add_row("Manifesto", result.manifest_path or "N/A")
        
        console.print(table)
        
    except Exception as e:
        console.print(f"[red]Erro: {e}[/red]")
        sys.exit(1)


# =============================================================================
# Comando: info
# =============================================================================
@cli.command('info')
def info():
    """Mostra informações sobre o framework."""
    
    table = Table(title="TCC Forense Cloud")
    table.add_column("Componente", style="cyan")
    table.add_column("Status")
    
    table.add_row("Core (hasher)", "[green]OK[/green]")
    table.add_row("Core (manifest)", "[green]OK[/green]")
    table.add_row("Docker Collector", "[green]OK[/green]" if DockerCollector else "[yellow]SDK não instalado[/yellow]")
    
    console.print(table)


if __name__ == '__main__':
    cli()

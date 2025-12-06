# =============================================================================
# TCC Forense Cloud - Script de Inicialização (Windows PowerShell)
# =============================================================================
# Uso: .\scripts\init_project.ps1
# =============================================================================

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  TCC Forense Cloud - Inicialização        " -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Verificar se está no diretório correto
if (-not (Test-Path ".\README.md")) {
    Write-Host "ERRO: Execute este script na raiz do projeto" -ForegroundColor Red
    exit 1
}

# 1. Criar ambiente virtual
Write-Host "[1/5] Criando ambiente virtual..." -ForegroundColor Yellow
if (-not (Test-Path ".\.venv")) {
    python -m venv .venv
    Write-Host "  Ambiente virtual criado!" -ForegroundColor Green
} else {
    Write-Host "  Ambiente virtual já existe" -ForegroundColor Gray
}

# 2. Ativar ambiente virtual
Write-Host "[2/5] Ativando ambiente virtual..." -ForegroundColor Yellow
& .\.venv\Scripts\Activate.ps1

# 3. Atualizar pip
Write-Host "[3/5] Atualizando pip..." -ForegroundColor Yellow
python -m pip install --upgrade pip

# 4. Instalar dependências
Write-Host "[4/5] Instalando dependências..." -ForegroundColor Yellow
pip install -r requirements.txt

# 5. Instalar pacote em modo desenvolvimento
Write-Host "[5/5] Instalando pacote..." -ForegroundColor Yellow
pip install -e .

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Inicialização Concluída!                 " -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Comandos úteis:" -ForegroundColor Yellow
Write-Host "  Ativar ambiente: .\.venv\Scripts\Activate.ps1"
Write-Host "  Executar testes: pytest tests/ -v"
Write-Host "  Ver ajuda CLI:   python -m src.cli.main --help"
Write-Host "  Calcular hash:   python -m src.cli.main hash arquivo.txt"
Write-Host ""

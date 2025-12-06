# Guia de Instalação — Windows + VS Code

## Visão Geral

Este guia detalha a instalação de todas as ferramentas necessárias para o projeto de TCC no Windows.

**Tempo estimado:** 1-2 horas  
**Sistema:** Windows 10/11  
**IDE:** Visual Studio Code

---

## Pré-requisitos

- Windows 10 (versão 1903+) ou Windows 11
- Conta de administrador
- Conexão com internet
- ~10 GB de espaço livre em disco

---

## 1. Python 3.11+

### Instalação

1. Acesse: https://www.python.org/downloads/
2. Baixe a versão **Python 3.11.x** ou superior
3. Execute o instalador e **MARQUE** as opções:
   - ☑️ **Add Python to PATH** (IMPORTANTE!)
   - ☑️ Install for all users

4. Clique em "Install Now"

### Verificação (PowerShell)

```powershell
python --version
# Esperado: Python 3.11.x

pip --version
# Esperado: pip 23.x.x
```

### Solução de Problemas

Se `python` não for reconhecido:
```powershell
# Verificar se está no PATH
$env:PATH -split ';' | Select-String -Pattern "Python"

# Adicionar manualmente (substitua pelo seu caminho)
$env:PATH += ";C:\Users\SEU_USUARIO\AppData\Local\Programs\Python\Python311"
$env:PATH += ";C:\Users\SEU_USUARIO\AppData\Local\Programs\Python\Python311\Scripts"
```

---

## 2. Git

### Instalação

1. Acesse: https://git-scm.com/download/win
2. Baixe e execute o instalador
3. Durante a instalação, aceite as opções padrão, mas verifique:
   - ☑️ Git from the command line and also from 3rd-party software
   - ☑️ Use Visual Studio Code as Git's default editor
   - ☑️ Override the default branch name: **main**

### Verificação

```powershell
git --version
# Esperado: git version 2.x.x
```

### Configuração Inicial

```powershell
git config --global user.name "Seu Nome"
git config --global user.email "seu.email@exemplo.com"
git config --global init.defaultBranch main
```

---

## 3. Visual Studio Code

### Instalação

1. Acesse: https://code.visualstudio.com/
2. Baixe e instale

### Extensões Recomendadas

Abra o VS Code e instale (Ctrl+Shift+X):

| Extensão | ID | Função |
|----------|-----|--------|
| Python | ms-python.python | Suporte a Python |
| Pylance | ms-python.vscode-pylance | IntelliSense avançado |
| Docker | ms-azuretools.vscode-docker | Suporte a Docker |
| GitLens | eamodio.gitlens | Git avançado |
| YAML | redhat.vscode-yaml | Suporte a YAML |
| Thunder Client | rangav.vscode-thunder-client | Testar APIs |

Ou instale via PowerShell:
```powershell
code --install-extension ms-python.python
code --install-extension ms-python.vscode-pylance
code --install-extension ms-azuretools.vscode-docker
code --install-extension eamodio.gitlens
```

---

## 4. Docker Desktop

### Pré-requisito: WSL2

O Docker Desktop no Windows requer WSL2. Instale primeiro:

```powershell
# PowerShell como Administrador
wsl --install
```

Reinicie o computador se solicitado.

### Instalação do Docker Desktop

1. Acesse: https://www.docker.com/products/docker-desktop/
2. Baixe "Docker Desktop for Windows"
3. Execute o instalador
4. Marque: ☑️ Use WSL 2 instead of Hyper-V
5. Após instalação, reinicie o computador

### Verificação

```powershell
docker --version
# Esperado: Docker version 24.x.x

docker run --rm hello-world
# Esperado: Mensagem "Hello from Docker!"
```

### Solução de Problemas

Se Docker não iniciar:
1. Verifique se WSL2 está instalado: `wsl --status`
2. Abra Docker Desktop manualmente
3. Verifique se está rodando no ícone da bandeja do sistema

---

## 5. kubectl (Kubernetes CLI)

### Instalação via winget (recomendado)

```powershell
winget install Kubernetes.kubectl
```

### Instalação Manual (alternativa)

```powershell
# Criar pasta
mkdir ~\.kube -Force

# Baixar kubectl
curl.exe -LO "https://dl.k8s.io/release/v1.29.0/bin/windows/amd64/kubectl.exe"

# Mover para pasta no PATH
Move-Item kubectl.exe C:\Windows\System32\
```

### Verificação

```powershell
kubectl version --client
# Esperado: Client Version: v1.29.x
```

---

## 6. AWS CLI v2

### Instalação

```powershell
# Baixar e instalar
msiexec.exe /i https://awscli.amazonaws.com/AWSCLIV2.msi /quiet
```

Ou baixe manualmente: https://awscli.amazonaws.com/AWSCLIV2.msi

### Verificação

```powershell
# Feche e reabra o PowerShell primeiro
aws --version
# Esperado: aws-cli/2.x.x Python/3.x.x Windows/10
```

### Configuração (para uso futuro)

```powershell
aws configure
# AWS Access Key ID: [deixe vazio por enquanto ou use sua key]
# AWS Secret Access Key: [deixe vazio por enquanto]
# Default region name: us-east-1
# Default output format: json
```

---

## 7. Azure CLI

### Instalação via winget (recomendado)

```powershell
winget install Microsoft.AzureCLI
```

### Instalação Manual (alternativa)

Baixe: https://aka.ms/installazurecliwindows

### Verificação

```powershell
# Feche e reabra o PowerShell primeiro
az --version
# Esperado: azure-cli 2.x.x
```

---

## 8. Google Cloud SDK (gcloud)

### Instalação

1. Acesse: https://cloud.google.com/sdk/docs/install
2. Baixe o instalador para Windows
3. Execute e siga as instruções
4. Marque: ☑️ Run 'gcloud init' after installation

### Verificação

```powershell
gcloud --version
# Esperado: Google Cloud SDK x.x.x
```

---

## 9. Verificação Final Completa

### Script de Verificação

Salve como `verificar_ambiente.ps1` e execute:

```powershell
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  VERIFICAÇÃO DO AMBIENTE - TCC FORENSE    " -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$ferramentas = @(
    @{Nome="Python"; Comando="python --version"},
    @{Nome="pip"; Comando="pip --version"},
    @{Nome="Git"; Comando="git --version"},
    @{Nome="Docker"; Comando="docker --version"},
    @{Nome="kubectl"; Comando="kubectl version --client --short 2>&1"},
    @{Nome="AWS CLI"; Comando="aws --version"},
    @{Nome="Azure CLI"; Comando="az version --output tsv 2>&1 | Select-Object -First 1"},
    @{Nome="gcloud"; Comando="gcloud --version 2>&1 | Select-Object -First 1"}
)

$totalOk = 0
$totalFalha = 0

foreach ($f in $ferramentas) {
    Write-Host "$($f.Nome): " -NoNewline
    try {
        $resultado = Invoke-Expression $f.Comando 2>&1
        if ($LASTEXITCODE -eq 0 -or $resultado -match "\d+\.\d+") {
            Write-Host "OK" -ForegroundColor Green
            Write-Host "  $resultado" -ForegroundColor Gray
            $totalOk++
        } else {
            Write-Host "FALHA" -ForegroundColor Red
            $totalFalha++
        }
    } catch {
        Write-Host "NÃO INSTALADO" -ForegroundColor Red
        $totalFalha++
    }
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Resultado: $totalOk OK, $totalFalha com problema" -ForegroundColor $(if($totalFalha -eq 0){"Green"}else{"Yellow"})
Write-Host "============================================" -ForegroundColor Cyan
```

### Resultado Esperado

```
============================================
  VERIFICAÇÃO DO AMBIENTE - TCC FORENSE    
============================================

Python: OK
  Python 3.11.x
pip: OK
  pip 23.x.x
Git: OK
  git version 2.x.x
Docker: OK
  Docker version 24.x.x
kubectl: OK
  Client Version: v1.29.x
AWS CLI: OK
  aws-cli/2.x.x
Azure CLI: OK
  azure-cli 2.x.x
gcloud: OK
  Google Cloud SDK x.x.x

============================================
Resultado: 8 OK, 0 com problema
============================================
```

---

## Ordem de Instalação Recomendada

1. ✅ Git (necessário para VS Code e versionamento)
2. ✅ Python 3.11+ (linguagem principal)
3. ✅ VS Code + Extensões (IDE)
4. ✅ Docker Desktop (requer reinício)
5. ✅ kubectl
6. ✅ AWS CLI
7. ✅ Azure CLI
8. ✅ gcloud

---

## Próximos Passos

Após todas as verificações passarem:

1. Criar o repositório do projeto (T2)
2. Configurar ambiente virtual Python
3. Instalar dependências do projeto

Siga para: **T2 - Estruturação do Repositório**

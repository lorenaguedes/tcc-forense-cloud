# TCC: Perícia Digital em Ambientes de Nuvem

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 📋 Descrição

Framework para **Perícia Digital em Ambientes de Computação em Nuvem e Redes Distribuídas**, utilizando:

- **Inteligência Artificial** para análise automatizada de evidências
- **Blockchain** para garantia da cadeia de custódia

**Autor:** [Seu Nome]  
**Orientador:** [Nome do Orientador]  
**Instituição:** [Nome da Instituição]  
**Ano:** 2025

---

## 🏗️ Estrutura do Projeto

```
tcc-forense-cloud/
├── src/                        # Código-fonte
│   ├── core/                   # Módulos centrais
│   │   ├── hasher.py           # Hashing forense (SHA-256)
│   │   └── manifest.py         # Gerador de manifesto
│   ├── collectors/             # Coletores de evidências
│   │   ├── aws_collector.py    # Amazon Web Services
│   │   ├── azure_collector.py  # Microsoft Azure
│   │   ├── gcp_collector.py    # Google Cloud Platform
│   │   ├── docker_collector.py # Docker
│   │   └── k8s_collector.py    # Kubernetes
│   └── cli/                    # Interface de linha de comando
│       └── main.py
├── tests/                      # Testes automatizados
│   ├── unit/                   # Testes unitários
│   └── integration/            # Testes de integração
├── docs/                       # Documentação
├── scripts/                    # Scripts auxiliares
├── config/                     # Arquivos de configuração
├── output/                     # Saída de coletas (gitignored)
└── notebooks/                  # Jupyter notebooks
```

---

## 🚀 Início Rápido

### Pré-requisitos

- Python 3.11 ou superior
- Docker Desktop
- Git

### Instalação

```powershell
# 1. Clone o repositório
git clone https://github.com/seu-usuario/tcc-forense-cloud.git
cd tcc-forense-cloud

# 2. Crie o ambiente virtual
python -m venv .venv

# 3. Ative o ambiente virtual (Windows PowerShell)
.\.venv\Scripts\Activate.ps1

# 4. Instale as dependências
pip install -r requirements.txt

# 5. Instale o pacote em modo desenvolvimento
pip install -e .
```

### Uso Básico

```powershell
# Verificar instalação
python -m src.cli.main --version

# Calcular hash de um arquivo
python -m src.cli.main hash .\arquivo.txt

# Coletar evidências Docker (exemplo)
python -m src.cli.main collect docker --case-id CASO-2025-001 --source all_containers

# Verificar integridade de evidências
python -m src.cli.main verify --manifest .\output\manifest.json
```

---

## 📦 Módulos

### Core

| Módulo | Descrição |
|--------|-----------|
| `hasher.py` | Cálculo de hashes SHA-256/512 para integridade forense |
| `manifest.py` | Geração de manifestos JSON com cadeia de custódia |

### Coletores

| Coletor | Fontes Suportadas |
|---------|-------------------|
| AWS | CloudTrail, S3 Access Logs, EC2 Metadata, VPC Flow Logs |
| Azure | Activity Log, Blob Storage, VM Metadata |
| GCP | Cloud Logging, Cloud Storage, Compute Metadata |
| Docker | Container Logs, Inspect, Images, Networks |
| Kubernetes | Pod Logs, Events, Resources, ConfigMaps |

---

## 🧪 Testes

```powershell
# Executar todos os testes
pytest tests/ -v

# Apenas testes unitários
pytest tests/unit/ -v

# Com cobertura de código
pytest tests/ -v --cov=src --cov-report=html
```

---

## 📚 Documentação

- [Guia de Instalação (Windows)](docs/GUIA_INSTALACAO_WINDOWS.md)
- [Metodologia Forense](docs/METODOLOGIA_FORENSE.md)
- [Referência da API](docs/API_REFERENCE.md)

---

## ⚖️ Considerações Éticas e Legais

⚠️ **IMPORTANTE:** Este framework foi desenvolvido para fins acadêmicos e de pesquisa.

- Colete evidências apenas de sistemas para os quais você possui **autorização expressa**
- Observe a **LGPD** (Lei Geral de Proteção de Dados) e legislações aplicáveis
- Mantenha a **cadeia de custódia** documentada
- Dados coletados podem conter **informações sensíveis**

---

## 📖 Referências

1. ALSHABIBI, M. M. et al. (2024). Forensic Investigation, Challenges, and Issues of Cloud Data. MDPI.
2. JARRETT, A.; CHOO, K.-K. R. (2021). The impact of automation and artificial intelligence on digital forensics. WIREs Forensic Science.
3. NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response.
4. ISO/IEC 27037:2012: Guidelines for digital evidence.

---

## 📄 Licença

Este projeto está licenciado sob a [MIT License](LICENSE).

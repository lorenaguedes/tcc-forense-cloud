"""Setup do pacote TCC Forense Cloud."""

from setuptools import setup, find_packages
from pathlib import Path

readme = Path("README.md").read_text(encoding="utf-8")

setup(
    name="tcc-forense-cloud",
    version="1.0.0",
    author="Seu Nome",
    description="Framework de Perícia Digital em Nuvem",
    long_description=readme,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "click>=8.1.0",
        "rich>=13.0.0",
        "structlog>=24.1.0",
        "pyyaml>=6.0.0",
        "python-dotenv>=1.0.0",
    ],
    extras_require={
        "docker": ["docker>=7.0.0"],
        "dev": ["pytest>=8.0.0", "pytest-cov>=4.1.0", "black>=24.1.0"],
    },
    entry_points={
        "console_scripts": [
            "forense-cloud=src.cli.main:cli",
        ],
    },
)

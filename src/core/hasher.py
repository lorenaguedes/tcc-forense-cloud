"""
Módulo de Hashing Forense
=========================

Implementa cálculo de hashes criptográficos para garantir
a integridade das evidências digitais coletadas.

Referências:
    - NIST SP 800-86: Guide to Integrating Forensic Techniques
    - RFC 6234: US Secure Hash Algorithms

Autor: [Seu Nome]
"""

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Union

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class HashResult:
    """Resultado do cálculo de hash de uma evidência."""
    
    algorithm: str
    hash_value: str
    file_path: str
    file_size: int
    calculated_at: str
    verified: bool = False
    
    def to_dict(self) -> dict:
        """Converte para dicionário (serialização JSON)."""
        return {
            "algorithm": self.algorithm,
            "hash_value": self.hash_value,
            "file_path": self.file_path,
            "file_size_bytes": self.file_size,
            "calculated_at_utc": self.calculated_at,
            "verified": self.verified
        }


class ForensicHasher:
    """
    Classe principal para cálculo de hashes forenses.
    
    Implementa SHA-256 como algoritmo padrão, conforme NIST.
    
    Example:
        >>> hasher = ForensicHasher()
        >>> result = hasher.hash_file("evidencia.log")
        >>> print(result.hash_value)
    """
    
    SUPPORTED_ALGORITHMS = {
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512,
        'sha3_256': hashlib.sha3_256,
        'sha3_512': hashlib.sha3_512,
        'blake2b': hashlib.blake2b,
    }
    
    DEFAULT_CHUNK_SIZE = 65536  # 64KB
    
    def __init__(
        self,
        algorithm: str = 'sha256',
        chunk_size: int = DEFAULT_CHUNK_SIZE
    ):
        """
        Inicializa o hasher forense.
        
        Args:
            algorithm: Algoritmo de hash ('sha256', 'sha512', etc.)
            chunk_size: Tamanho do chunk para leitura
        """
        algorithm = algorithm.lower()
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            supported = ', '.join(self.SUPPORTED_ALGORITHMS.keys())
            raise ValueError(
                f"Algoritmo '{algorithm}' não suportado. "
                f"Disponíveis: {supported}"
            )
        
        self.algorithm = algorithm
        self.chunk_size = chunk_size
        self._hash_constructor = self.SUPPORTED_ALGORITHMS[algorithm]
        
        logger.info("ForensicHasher inicializado", algorithm=algorithm)
    
    def hash_file(self, file_path: Union[str, Path]) -> HashResult:
        """
        Calcula o hash de um arquivo.
        
        Args:
            file_path: Caminho para o arquivo
            
        Returns:
            HashResult com os detalhes do cálculo
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"Arquivo não encontrado: {file_path}")
        
        if not file_path.is_file():
            raise ValueError(f"Caminho não é um arquivo: {file_path}")
        
        logger.info("Calculando hash", file=str(file_path))
        
        timestamp = datetime.now(timezone.utc).isoformat()
        hasher = self._hash_constructor()
        file_size = 0
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(self.chunk_size):
                hasher.update(chunk)
                file_size += len(chunk)
        
        hash_value = hasher.hexdigest()
        
        result = HashResult(
            algorithm=self.algorithm,
            hash_value=hash_value,
            file_path=str(file_path.absolute()),
            file_size=file_size,
            calculated_at=timestamp
        )
        
        logger.info(
            "Hash calculado",
            file=str(file_path),
            hash=hash_value[:16] + "..."
        )
        
        return result
    
    def hash_bytes(self, data: bytes) -> str:
        """Calcula o hash de dados em memória."""
        hasher = self._hash_constructor()
        hasher.update(data)
        return hasher.hexdigest()
    
    def hash_stream(self, stream: BinaryIO) -> str:
        """Calcula o hash de um stream binário."""
        hasher = self._hash_constructor()
        while chunk := stream.read(self.chunk_size):
            hasher.update(chunk)
        return hasher.hexdigest()
    
    def verify_file(self, file_path: Union[str, Path], expected_hash: str) -> bool:
        """
        Verifica se o hash de um arquivo corresponde ao esperado.
        
        Args:
            file_path: Caminho para o arquivo
            expected_hash: Hash esperado (hexadecimal)
            
        Returns:
            True se os hashes correspondem
        """
        result = self.hash_file(file_path)
        matches = result.hash_value.lower() == expected_hash.lower()
        
        if matches:
            logger.info("Verificação OK", file=str(file_path))
        else:
            logger.warning("Verificação FALHOU", file=str(file_path))
        
        return matches
    
    def hash_directory(
        self,
        directory_path: Union[str, Path],
        recursive: bool = True,
        pattern: str = "*"
    ) -> list[HashResult]:
        """Calcula hashes de todos os arquivos em um diretório."""
        directory_path = Path(directory_path)
        
        if not directory_path.is_dir():
            raise NotADirectoryError(f"Não é um diretório: {directory_path}")
        
        results = []
        glob_method = directory_path.rglob if recursive else directory_path.glob
        
        for file_path in sorted(glob_method(pattern)):
            if file_path.is_file():
                try:
                    result = self.hash_file(file_path)
                    results.append(result)
                except (PermissionError, IOError) as e:
                    logger.warning(f"Falha ao processar {file_path}: {e}")
        
        return results


# Funções de conveniência
def calculate_sha256(file_path: Union[str, Path]) -> str:
    """Cálculo rápido de SHA-256."""
    hasher = ForensicHasher(algorithm='sha256')
    return hasher.hash_file(file_path).hash_value


def verify_sha256(file_path: Union[str, Path], expected_hash: str) -> bool:
    """Verificação rápida de SHA-256."""
    hasher = ForensicHasher(algorithm='sha256')
    return hasher.verify_file(file_path, expected_hash)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Uso: python hasher.py <arquivo> [algoritmo]")
        sys.exit(1)
    
    file_path = sys.argv[1]
    algorithm = sys.argv[2] if len(sys.argv) > 2 else 'sha256'
    
    hasher = ForensicHasher(algorithm=algorithm)
    result = hasher.hash_file(file_path)
    
    print(f"Arquivo: {result.file_path}")
    print(f"Algoritmo: {result.algorithm}")
    print(f"Hash: {result.hash_value}")
    print(f"Tamanho: {result.file_size} bytes")

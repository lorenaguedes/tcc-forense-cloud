"""
Testes Unitários - Módulo de Hashing
"""

import hashlib
import os
import tempfile
import pytest

from src.core.hasher import ForensicHasher, HashResult, calculate_sha256, verify_sha256


class TestForensicHasher:
    """Testes para ForensicHasher."""
    
    def test_init_default(self):
        hasher = ForensicHasher()
        assert hasher.algorithm == 'sha256'
    
    def test_init_custom_algorithm(self):
        hasher = ForensicHasher(algorithm='sha512')
        assert hasher.algorithm == 'sha512'
    
    def test_init_invalid_algorithm(self):
        with pytest.raises(ValueError, match="não suportado"):
            ForensicHasher(algorithm='md5')
    
    def test_hash_file(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("Conteúdo de teste" * 100)
            temp_path = f.name
        
        try:
            hasher = ForensicHasher()
            result = hasher.hash_file(temp_path)
            
            assert isinstance(result, HashResult)
            assert result.algorithm == 'sha256'
            assert len(result.hash_value) == 64
            assert result.file_size > 0
        finally:
            os.unlink(temp_path)
    
    def test_hash_file_matches_hashlib(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            content = "Teste de verificação"
            f.write(content)
            temp_path = f.name
        
        try:
            hasher = ForensicHasher()
            result = hasher.hash_file(temp_path)
            
            with open(temp_path, 'rb') as f:
                expected = hashlib.sha256(f.read()).hexdigest()
            
            assert result.hash_value == expected
        finally:
            os.unlink(temp_path)
    
    def test_hash_file_not_found(self):
        hasher = ForensicHasher()
        with pytest.raises(FileNotFoundError):
            hasher.hash_file('/caminho/inexistente.txt')
    
    def test_hash_bytes(self):
        hasher = ForensicHasher()
        data = b"Dados em memoria"
        
        result = hasher.hash_bytes(data)
        expected = hashlib.sha256(data).hexdigest()
        
        assert result == expected
    
    def test_verify_file_valid(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("Conteúdo para verificar")
            temp_path = f.name
        
        try:
            hasher = ForensicHasher()
            result = hasher.hash_file(temp_path)
            
            assert hasher.verify_file(temp_path, result.hash_value) is True
        finally:
            os.unlink(temp_path)
    
    def test_verify_file_invalid(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("Conteúdo")
            temp_path = f.name
        
        try:
            hasher = ForensicHasher()
            assert hasher.verify_file(temp_path, "a" * 64) is False
        finally:
            os.unlink(temp_path)


class TestConvenienceFunctions:
    """Testes para funções de conveniência."""
    
    def test_calculate_sha256(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("Teste")
            temp_path = f.name
        
        try:
            hash_value = calculate_sha256(temp_path)
            assert len(hash_value) == 64
        finally:
            os.unlink(temp_path)
    
    def test_verify_sha256(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("Teste")
            temp_path = f.name
        
        try:
            hash_value = calculate_sha256(temp_path)
            assert verify_sha256(temp_path, hash_value) is True
            assert verify_sha256(temp_path, "x" * 64) is False
        finally:
            os.unlink(temp_path)

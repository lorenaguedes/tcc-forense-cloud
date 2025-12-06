"""
Testes Unitários - Módulo de Manifesto
"""

import json
import os
import tempfile
import pytest

from src.core.manifest import (
    ManifestGenerator,
    AgentInfo,
    SourceInfo,
    EvidenceItem,
    create_manifest
)


class TestAgentInfo:
    def test_create(self):
        agent = AgentInfo(name="Perito", agent_id="P001")
        assert agent.name == "Perito"
        assert agent.agent_id == "P001"
        assert agent.hostname is not None


class TestSourceInfo:
    def test_create(self):
        source = SourceInfo(source_type="docker", provider="docker")
        assert source.source_type == "docker"


class TestManifestGenerator:
    def test_init(self):
        gen = ManifestGenerator(
            case_id="CASO-001",
            agent_name="Perito",
            agent_id="P001"
        )
        assert gen.manifest.case_id == "CASO-001"
        assert gen.manifest.collection_id is not None
    
    def test_set_source(self):
        gen = ManifestGenerator(case_id="CASO-001", agent_name="P", agent_id="P1")
        gen.set_source("docker_logs", "docker", container_id="abc")
        
        assert gen.manifest.source.source_type == "docker_logs"
        assert gen.manifest.source.provider == "docker"
    
    def test_add_evidence_file(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("Evidência de teste")
            temp_path = f.name
        
        try:
            gen = ManifestGenerator(case_id="CASO-001", agent_name="P", agent_id="P1")
            gen.set_source("test", "test")
            
            evidence = gen.add_evidence_file(temp_path)
            
            assert evidence.filename == os.path.basename(temp_path)
            assert len(evidence.sha256) == 64
            assert len(gen.manifest.evidence_items) == 1
        finally:
            os.unlink(temp_path)
    
    def test_add_evidence_bytes(self):
        gen = ManifestGenerator(case_id="CASO-001", agent_name="P", agent_id="P1")
        gen.set_source("test", "test")
        
        data = b"Dados em memoria"
        evidence = gen.add_evidence_bytes(data, filename="memory.bin")
        
        assert evidence.filename == "memory.bin"
        assert evidence.size_bytes == len(data)
        assert evidence.local_path == "[in-memory]"
    
    def test_finalize(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("Evidência")
            temp_path = f.name
        
        try:
            gen = ManifestGenerator(case_id="CASO-001", agent_name="P", agent_id="P1")
            gen.set_source("test", "test")
            gen.add_evidence_file(temp_path)
            
            manifest = gen.finalize()
            
            assert manifest.ready_for_blockchain is True
            assert len(manifest.manifest_hash) == 64
        finally:
            os.unlink(temp_path)
    
    def test_to_json(self):
        gen = ManifestGenerator(case_id="CASO-001", agent_name="P", agent_id="P1")
        gen.set_source("test", "test")
        gen.finalize()
        
        json_str = gen.to_json()
        data = json.loads(json_str)
        
        assert data['case_id'] == "CASO-001"
    
    def test_save_and_load(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Criar arquivo de evidência
            evidence_path = os.path.join(tmpdir, "evidence.txt")
            with open(evidence_path, 'w') as f:
                f.write("Evidência")
            
            # Criar e salvar manifesto
            gen = ManifestGenerator(case_id="CASO-001", agent_name="P", agent_id="P1")
            gen.set_source("test", "test")
            gen.add_evidence_file(evidence_path)
            
            manifest_path = os.path.join(tmpdir, "manifest.json")
            gen.save(manifest_path)
            
            assert os.path.exists(manifest_path)
            
            # Carregar
            loaded = ManifestGenerator.load(manifest_path)
            assert loaded.manifest.case_id == "CASO-001"
            assert len(loaded.manifest.evidence_items) == 1


class TestCreateManifest:
    def test_convenience_function(self):
        gen = create_manifest(
            case_id="CASO-001",
            agent_name="Perito",
            agent_id="P001",
            source_type="docker",
            provider="docker"
        )
        
        assert isinstance(gen, ManifestGenerator)
        assert gen.manifest.source.source_type == "docker"

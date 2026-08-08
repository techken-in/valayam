import subprocess
import tempfile
import json
import os
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class ValayamClient:
    def __init__(self, workspace_dir: str, grpc_worker: str = None):
        self.workspace_dir = workspace_dir
        self.grpc_worker = grpc_worker

    def run_scan(self, target: str, template_path: str) -> List[Dict[str, Any]]:
        """
        Executes valayam scan against a target. Routes to gRPC if worker is configured,
        otherwise falls back to running valayam-cli via subprocess.
        """
        if self.grpc_worker:
            return self.run_scan_grpc(target, template_path)
        return self.run_scan_cli(target, template_path)

    def run_scan_cli(self, target: str, template_path: str) -> List[Dict[str, Any]]:
        """
        Executes valayam-cli against a target using the specified template path.
        Returns a list of finding objects.
        """
        findings = []
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            output_file = tmp.name
        
        try:
            cmd = [
                "cargo", "run", "--bin", "valayam-cli", "--",
                "-u", target,
                "-t", template_path,
                "-o", output_file
            ]
            
            logger.info(f"Running command: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                cwd=self.workspace_dir,
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                logger.error(f"Valayam scan failed:\n{result.stderr}")
            
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file, "r") as f:
                    for line in f:
                        if line.strip():
                            findings.append(json.loads(line.strip()))
                            
        finally:
            if os.path.exists(output_file):
                os.remove(output_file)
                
        return findings

    def run_scan_grpc(self, target: str, template_path: str) -> List[Dict[str, Any]]:
        """
        Runs the scan by connecting to a remote valayam-worker via gRPC.
        """
        import grpc
        import valayam_pb2
        import valayam_pb2_grpc

        logger.info(f"Connecting to Valayam worker via gRPC at {self.grpc_worker}...")
        try:
            with open(template_path, "r") as f:
                template_yaml = f.read()

            channel = grpc.insecure_channel(self.grpc_worker)
            stub = valayam_pb2_grpc.ScannerStub(channel)
            
            req = valayam_pb2.ScanRequest(
                template_yaml=template_yaml,
                target_url=target
            )
            
            response = stub.Scan(req)
            findings = []
            for finding_json in response.findings_json:
                try:
                    findings.append(json.loads(finding_json))
                except Exception as e:
                    logger.error(f"Failed to parse gRPC finding JSON: {e}")
            return findings
        except Exception as e:
            logger.error(f"gRPC scan failed: {e}")
            return []


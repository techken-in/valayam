import os
import json
import yaml
import tempfile
from pydantic import BaseModel, Field
from typing import List, Dict, Any
from valayam_client import ValayamClient
from openai import OpenAI

class VulnerabilityTemplate(BaseModel):
    id: str
    info: dict
    requests: list = []
    network: list = []
    dns: list = []
    tls: list = []
    scripts: list = []

class AIAgent:
    def __init__(self, workspace_dir: str, api_key: str = None, grpc_worker: str = None):
        self.client = ValayamClient(workspace_dir, grpc_worker=grpc_worker)
        self.llm = OpenAI(api_key=api_key or os.environ.get("OPENAI_API_KEY", "dummy-key"))

    def generate_template(self, instruction: str) -> dict:
        """Uses LLM to dynamically generate a Valayam DSL template based on the instruction."""
        prompt = f"""
You are a security expert. Generate a Valayam scanner template in YAML for the following goal:
"{instruction}"

Return ONLY valid YAML. No markdown formatting.
        """
        
        # Note: In a real scenario, this would call the LLM API. 
        # For demonstration (MVP), if the API key is missing or dummy, we return a fallback.
        try:
            response = self.llm.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0
            )
            yaml_content = response.choices[0].message.content.strip()
            if yaml_content.startswith("```yaml"):
                yaml_content = yaml_content[7:]
            if yaml_content.endswith("```"):
                yaml_content = yaml_content[:-3]
                
            return yaml.safe_load(yaml_content)
        except Exception as e:
            print(f"[!] LLM Generation failed: {e}. Falling back to default template.")
            # Fallback template for testing without a real OpenAI key
            return {
                "id": "ai-generated-test",
                "info": {
                    "name": "AI Generated Default Scan",
                    "severity": "Info",
                    "description": "Fallback template for MVP"
                },
                "requests": [{
                    "method": "GET",
                    "path": "/",
                    "matchers": [{
                        "type": "status",
                        "part": "status",
                        "status": [200]
                    }]
                }]
            }

    def decide_next_step(self, target: str, instruction: str, history: List[Dict[str, Any]], findings: List[Dict[str, Any]]) -> str:
        """Asks the LLM to decide on the next scan template or to STOP."""
        prompt = f"""
You are an autonomous security agent orchestrating a vulnerability scanner against target: {target}
Overall Goal: "{instruction}"

Here is the history of previous scans:
{json.dumps(history, indent=2)}

Here are all the findings gathered so far:
{json.dumps(findings, indent=2)}

Decide on the next action:
- If the goal has been fully met, or if no further scanning is logical or safe, respond with exactly: STOP
- Otherwise, generate a new Valayam YAML scanner template to proceed with the next phase of reconnaissance or verification.
Return ONLY valid Valayam scanner YAML, or the word STOP. No markdown formatting.
"""
        try:
            response = self.llm.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            print(f"[!] LLM Decision failed: {e}. Defaulting to STOP.")
            return "STOP"

    def execute_goal(self, target: str, instruction: str) -> List[Dict[str, Any]]:
        """Orchestrates an autonomous loop of scans to achieve the security goal."""
        print(f"[*] Starting Autonomous Recon Loop")
        print(f"[*] Goal: {instruction}")
        print(f"[*] Target: {target}")
        
        all_findings = []
        history = []
        max_steps = 5
        
        for step in range(1, max_steps + 1):
            print(f"\n--- [Step {step}/{max_steps}] ---")
            decision = self.decide_next_step(target, instruction, history, all_findings)
            
            # If LLM failed or dummy API key was used, we simulate a basic multi-step fallback
            if decision == "STOP" or "dummy-key" in str(self.llm.api_key):
                if step == 1:
                    print("[*] Running initial reconnaissance scan...")
                    decision = yaml.dump({
                        "id": "ai-initial-recon",
                        "info": {"name": "Initial Recon Scan", "severity": "Info"},
                        "requests": [{"method": "GET", "path": "/", "matchers": [{"type": "status", "part": "status", "status": [200]}]}]
                    })
                else:
                    print("[*] Goal met or stopped by agent.")
                    break

            if decision.strip() == "STOP":
                print("[*] Agent decided to STOP. Overall goal reached or scanner completed.")
                break

            # Parse template
            try:
                if decision.startswith("```yaml"):
                    decision = decision[7:]
                if decision.endswith("```"):
                    decision = decision[:-3]
                template_dict = yaml.safe_load(decision)
            except Exception as e:
                print(f"[!] Failed to parse generated template YAML: {e}. Stopping.")
                break

            with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w") as tmp:
                yaml.dump(template_dict, tmp)
                template_path = tmp.name

            print(f"[*] Executing generated template '{template_dict.get('id', 'temp')}'...")
            try:
                step_findings = self.client.run_scan(target, template_path)
                print(f"[+] Step findings: {len(step_findings)} discovered.")
                all_findings.extend(step_findings)
                history.append({
                    "step": step,
                    "template_id": template_dict.get("id"),
                    "findings_count": len(step_findings)
                })
            finally:
                if os.path.exists(template_path):
                    os.remove(template_path)

        return all_findings

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Valayam AI Agent")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-i", "--instruction", required=True, help="Security objective")
    parser.add_argument("-w", "--worker", default=None, help="gRPC worker host:port (e.g. localhost:50051)")
    args = parser.parse_args()

    # The Rust workspace is two directories up (relative to services/ai)
    workspace_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    
    agent = AIAgent(workspace_dir, grpc_worker=args.worker)
    findings = agent.execute_goal(args.url, args.instruction)
    
    print("\n[+] AI Agent Findings:")
    print(json.dumps(findings, indent=2))

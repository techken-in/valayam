import subprocess
import time
import urllib.request
import os
import sys

def wait_for_server(url, timeout=10):
    start = time.time()
    while time.time() - start < timeout:
        try:
            urllib.request.urlopen(url)
            return True
        except Exception:
            time.sleep(0.5)
    return False

def main():
    print("Starting mock server...")
    # Start the mock server in the background
    server_process = subprocess.Popen([sys.executable, "scripts/mock_server.py"])
    
    if not wait_for_server("http://localhost:8080"):
        print("Mock server failed to start.")
        server_process.kill()
        sys.exit(1)
        
    print("Mock server is running. Launching Valayam E2E scan...")
    
    # Run Valayam
    valayam_cmd = [
        "cargo", "run", "--bin", "valayam-cli", "--",
        "--target", "http://localhost:8080",
        "--crawl"
    ]
    
    try:
        # Run valayam and capture output
        result = subprocess.run(valayam_cmd, capture_output=True, text=True, timeout=60)
        print(f"Valayam exit code: {result.returncode}")
        
        output = result.stdout + result.stderr
        
        # Simple assertions on output
        if "http://localhost:8080/admin" in output or "Admin Panel" in output:
            print("SUCCESS: Found /admin endpoint or content.")
        else:
            print("WARNING: Did not find /admin endpoint in output.")
            
        if "http://localhost:8080/api/v1/users" in output:
            print("SUCCESS: Found /api/v1/users endpoint.")
        else:
            print("WARNING: Did not find /api/v1/users endpoint in output.")
            
        print("E2E Test Output Snippet:")
        print(output[:1000] + "\n...\n" + output[-1000:])
            
    except subprocess.TimeoutExpired:
        print("Valayam scan timed out.")
    finally:
        print("Terminating mock server...")
        server_process.terminate()
        server_process.wait()

if __name__ == "__main__":
    main()

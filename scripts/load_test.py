import subprocess
import time
import urllib.request
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

def monitor_process(proc, interval=0.5):
    pass

def main():
    print("Starting MASS TARGET server...")
    server_process = subprocess.Popen([sys.executable, "scripts/mass_target.py"])
    
    if not wait_for_server("http://localhost:8081"):
        print("Mass server failed to start.")
        server_process.kill()
        sys.exit(1)
        
    print("Mass server is running. Launching Valayam Load Test (Crawler only)...")
    
    valayam_cmd = [
        "cargo", "run", "--release", "--bin", "valayam-cli", "--",
        "--target", "http://localhost:8081",
        "--crawl"
    ]
    
    start_time = time.time()
    
    try:
        # Popen to allow background monitoring
        valayam_proc = subprocess.Popen(valayam_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Just communicate
        stdout, stderr = valayam_proc.communicate(timeout=300)
        
        duration = time.time() - start_time
        print(f"\n[Result] Load Test Completed in {duration:.2f} seconds")
        print(f"Exit code: {valayam_proc.returncode}")
        
        # Check if endpoints were crawled
        crawled_count = stdout.count("Found endpoint:")
        if crawled_count == 0:
            crawled_count = stdout.count("Endpoint") # Adjust based on actual log output
            
        print(f"Found mention of endpoints ~ {crawled_count} times in stdout.")
        
    except subprocess.TimeoutExpired:
        print("Valayam scan timed out after 300s.")
    finally:
        print("Terminating mass target server...")
        server_process.terminate()
        server_process.wait()

if __name__ == "__main__":
    main()

import os
import subprocess
import shutil
import tempfile
import sys

def main():
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    wasm_dir = os.path.join(root_dir, "plugins-wasm")
    plugins_out_dir = os.path.join(root_dir, "plugins")
    
    os.makedirs(plugins_out_dir, exist_ok=True)
    
    # Use system temp directory for building to avoid polluting the repo
    temp_target_dir = os.path.join(tempfile.gettempdir(), "valayam-wasm-target")
    print(f"[*] Building WASM plugins in virtual workspace...")
    print(f"[*] Target directory redirected to: {temp_target_dir}")
    
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = temp_target_dir
    
    # Run cargo build in the virtual workspace
    try:
        subprocess.run(
            ["cargo", "build", "--release", "--target", "wasm32-wasip1"],
            cwd=wasm_dir,
            env=env,
            check=True
        )
    except subprocess.CalledProcessError as e:
        print(f"[!] Cargo build failed: {e}")
        sys.exit(1)
        
    print("[*] Build successful. Copying .wasm files to plugins directory...")
    
    wasm_release_dir = os.path.join(temp_target_dir, "wasm32-wasip1", "release")
    copied = 0
    
    for item in os.listdir(wasm_release_dir):
        if item.endswith(".wasm"):
            src_path = os.path.join(wasm_release_dir, item)
            dst_path = os.path.join(plugins_out_dir, item)
            shutil.copy2(src_path, dst_path)
            print(f"  -> Copied {item}")
            copied += 1
            
    print(f"[*] Done! {copied} WASM plugins deployed to {plugins_out_dir}")

if __name__ == "__main__":
    main()

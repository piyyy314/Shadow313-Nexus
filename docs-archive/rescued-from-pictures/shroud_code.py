import base64

def shroud_code(input_file, output_file):
    try:
        # 1. Read your original script
        with open(input_file, "r") as f:
            original_code = f.read()

        # 2. Encode the code into Base64 (Gibberish)
        encoded_bytes = base64.b64encode(original_code.encode("utf-8"))
        encoded_string = encoded_bytes.decode("utf-8")

        # 3. Create the 'Loader' script
        # This is what the hacker will see. 
        # It decodes the blob and runs it in memory using exec()
        shrouded_template = f"""
import base64 as b64
# Security Layer 1.0
_payload = "{encoded_string}"
exec(b64.b64decode(_payload).decode('utf-8'))
"""

        # 4. Save the shrouded version
        with open(output_file, "w") as f:
            f.write(shrouded_template)
            
        print(f"[√] Success! {input_file} has been shrouded into {output_file}")
        print("[!] The code is now unreadable to the naked eye.")

    except Exception as e:
        print(f"[X] Error during shrouding: {e}")

if __name__ == "__main__":
    # Example: Shrouding the Process Sentinel we just made
    shroud_code("sentinel.py", "system_core_service.py")
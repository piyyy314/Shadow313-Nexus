import base64

def base64_encode(data):
    return base64.b64encode(data).decode('utf-8')

def create_image_trap(input_image_path, output_file, listener_url):
    """
    Wraps a real image inside an HTML 'shell' that pings our listener.
    """
    try:
        # 1. Read the binary data of the real image
        with open(input_image_path, "rb") as img_file:
            img_data = img_file.read()

        # 2. Create the HTML wrapper
        # This displays the image but includes our hidden tracking pixel
        html_content = f"""
<html>
<body style="margin:0; background-color:black;">
    <img src="data:image/jpeg;base64,{base64_encode(img_data)}" style="width:100%;">
    
    <img src="{listener_url}" style="display:none;">
    
    <script>
        console.log("Access Logged.");
    </script>
</body>
</html>
"""
        # 3. Save the new 'Polyglot' file
        with open(output_file, "w") as f:
            f.write(html_content)
            
        print(f"[√] Trap Image created: {output_file}")
        print(f"[*] When opened, it will look like a photo but ping: {listener_url}")

    except Exception as e:
        print(f"[X] Error creating trap: {e}")

if __name__ == "__main__":
    # Example usage:
    # 1. Put a real photo named 'map.jpg' in the folder
    # 2. Run this script
    create_image_trap("map.jpg", "Confidential_Network_Map.png.html", "http://YOUR_IP:8888/tracker.gif")
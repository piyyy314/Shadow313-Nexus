from flask import Flask, request, jsonify, send_file
import pywebview
from pathlib import Path
import zipfile
import random

app = Flask(__name__)
BASE_DIR = Path("corpus")
BASE_DIR.mkdir(exist_ok=True)

# ---------------- Corpus Builder ----------------
def generate_samples(base_dir, count=10):
    files = []
    for i in range(count):
        fname = f"sample_{i}.txt"
        code = f"echo 'Synthetic malware sample {i}'"
        path = base_dir / fname
        path.write_text(code)
        files.append(fname)
    return files

@app.post("/generate")
def generate():
    data = request.get_json(silent=True) or {}
    count = int(data.get("count", 10))
    files = generate_samples(BASE_DIR, count)
    return jsonify({"ok": True, "files": files})

@app.get("/list_files")
def list_files():
    files = [f.name for f in BASE_DIR.glob("*")]
    return jsonify({"files": files})

@app.post("/preview_file")
def preview_file():
    filename = request.json.get("filename")
    target = BASE_DIR / filename
    if not target.exists():
        return jsonify({"ok": False, "sample": "File not found"})
    return jsonify({"ok": True, "file": filename, "sample": target.read_text(errors="ignore")})

@app.post("/download_file")
def download_file():
    filename = request.json.get("filename")
    target = BASE_DIR / filename
    return send_file(target, as_attachment=True)

@app.post("/download_zip")
def download_zip():
    files = request.json.get("files", [])
    zip_path = BASE_DIR / "selected.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        for fname in files:
            target = BASE_DIR / fname
            if target.exists():
                zf.write(target, arcname=fname)
    return send_file(zip_path, as_attachment=True)

@app.post("/preview_selected")
def preview_selected():
    files = request.json.get("files", [])
    samples = []
    for fname in files:
        target = BASE_DIR / fname
        if target.exists():
            samples.append({"file": fname, "sample": target.read_text(errors="ignore")})
    return jsonify({"ok": True, "samples": samples})

# ---------------- Quantum Module ----------------
def quantum_random_bits(n=8):
    return [random.choice([0,1]) for _ in range(n)]

def grover_search(dataset, target):
    return target if target in dataset else None

@app.get("/quantum_random")
def quantum_random():
    return jsonify({"random_bits": quantum_random_bits(16)})

@app.get("/quantum_search")
def quantum_search():
    dataset = list(range(100))
    target = random.choice(dataset)
    found = grover_search(dataset, target)
    return jsonify({"target": target, "found": found})

# ---------------- Analytics Module ----------------
def forecast_data_growth():
    growth = {
        "2025": 175,
        "2030": 400,
        "2035": 800
    }
    insights = [
        "Healthcare: exponential genomic + patient data",
        "Finance: real-time transaction analytics",
        "Cybersecurity: threat intelligence at exabyte scale"
    ]
    return {"growth_zettabytes": growth, "insights": insights}

@app.get("/data_forecast")
def data_forecast():
    return jsonify(forecast_data_growth())

# ---------------- Embedded HTML ----------------
INDEX_HTML = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Quantum Corpus Analytics App</title>
  <link id="hljs-theme" rel="stylesheet"
        href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css">
  <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    nav { margin-bottom: 20px; }
    nav button { margin-right: 10px; }
    .tab { display: none; }
    .tab.active { display: block; }
    .modal { display:none; position:fixed; top:0; left:0; width:100%; height:100%;
             background:rgba(0,0,0,0.6); }
    .modal-content { background:#fff; margin:10% auto; padding:20px; width:80%; }
    pre { background:#f4f4f4; padding:10px; overflow:auto; }
  </style>
</head>
<body>
  <h1>Quantum Corpus Analytics App</h1>
  <nav>
    <button onclick="showTab('corpus')">Corpus Builder</button>
    <button onclick="showTab('quantum')">Quantum Simulation</button>
    <button onclick="showTab('analytics')">Analytics Dashboard</button>
  </nav>

  <div id="corpus" class="tab active">
    <h2>Corpus Builder</h2>
    <label>Number of samples:</label>
    <input id="sampleCount" type="number" value="5">
    <button onclick="generateCorpus()">Generate Corpus</button>
    <button onclick="openPreview()">Preview Random Sample</button>
  </div>

  <div id="quantum" class="tab">
    <h2>Quantum Simulation</h2>
    <button onclick="getQuantumRandom()">Quantum Random Bits</button>
    <button onclick="runGroverSearch()">Grover Search Simulation</button>
    <pre id="quantumOutput"></pre>
  </div>

  <div id="analytics" class="tab">
    <h2>Analytics Dashboard</h2>
    <button onclick="getForecast()">Forecast Data Growth</button>
    <pre id="analyticsOutput"></pre>
  </div>

  <div id="previewModal" class="modal">
    <div class="modal-content">
      <h3>Sample Preview</h3>
      <p id="previewFile"></p>
      <pre><code id="previewBox" class="hljs"></code></pre>
      <label>Filter files:</label>
      <input id="filterBox" type="text" placeholder="Type to filter..." oninput="filterFiles()">
      <label>Select files (multi-select):</label>
      <select id="fileDropdown" multiple size="8"></select>
      <button onclick="openSelectedFile()">Open Selected</button>
      <button onclick="downloadSample()">Download This Sample</button>
      <button onclick="downloadSelectedZip()">Download Selected as ZIP</button>
      <button onclick="previewSelectedFiles()">Preview All Selected Files</button>
      <button onclick="copyPreview()">Copy to Clipboard</button>
      <button onclick="clearPreview()">Clear Preview</button>
      <button onclick="toggleTheme()">Toggle Theme</button>
      <button onclick="nextSample()">Next Sample</button>
      <button onclick="closePreview()">Close</button>
    </div>
  </div>

<script>
function showTab(id) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById(id).classList.add('active');
}
async function generateCorpus() {
  const count = document.getElementById("sampleCount").value;
  await fetch("/generate", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({count})});
  alert("Corpus generated!");
}
async function openPreview() {
  const res = await fetch("/list_files");
  const data = await res.json();
  const dropdown = document.getElementById("fileDropdown");
  dropdown.innerHTML = "";
  data.files.forEach(f => {const opt=document.createElement("option"); opt.value=f; opt.textContent=f; dropdown.appendChild(opt);});
  document.getElementById("previewModal").style.display="block";
  nextSample();
}
function closePreview(){document.getElementById("previewModal").style.display="none";}
async function nextSample(){
  const res=await fetch("/list_files"); const data=await res.json(); const files=data.files;
  const randomFile=files[Math.floor(Math.random()*files.length)];
  const previewRes=await fetch("/preview_file",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({filename:randomFile})});
  const previewData=await previewRes.json(); updatePreview(previewData.sample, previewData.file);
}
async function openSelectedFile(){
  const filename=document.getElementById("fileDropdown").value;
  const res=await fetch("/preview_file",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({filename})});
  const data=await res.json(); updatePreview(data.sample,data.file);
}
async function previewSelectedFiles(){
  const dropdown=document.getElementById("fileDropdown");
  const selected=Array.from(dropdown.selectedOptions).map(opt=>opt.value);
  const res=await fetch("/preview_selected",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({files:selected})});
  const data=await res.json(); let output="";
  data.samples.forEach(s=>{output+="File: "+s.file+"\\n"+s.sample
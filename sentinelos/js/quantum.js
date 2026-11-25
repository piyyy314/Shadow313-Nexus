// --- SENTINELOS Browser-Only PQC Concept Demo (Not Cryptographic) ---

(() => {
    let generatedKeys = false;
    let canvas, ctx;
    let animId;
    let gridPoints = [];
    let latticeScale = 1.0;
    let pulseWave = 0;
    let isPulsing = false;

    // Initialize module parameters
    window.initQuantumView = () => {
        canvas = document.getElementById('lattice-canvas');
        if (canvas) {
            ctx = canvas.getContext('2d');
            resizeLatticeCanvas();
            initLatticePoints();
            
            if (animId) cancelAnimationFrame(animId);
            animateLattice();
        }
    };

    const resizeLatticeCanvas = () => {
        if (!canvas) return;
        const rect = canvas.parentElement.getBoundingClientRect();
        canvas.width = rect.width;
        canvas.height = rect.height || 120;
    };

    window.addEventListener('resize', resizeLatticeCanvas);

    // Grid coordinates representation
    const initLatticePoints = () => {
        gridPoints = [];
        const cols = 20;
        const rows = 8;
        const spacingX = canvas.width / cols;
        const spacingY = canvas.height / rows;

        for (let r = 0; r < rows; r++) {
            for (let c = 0; c < cols; c++) {
                gridPoints.push({
                    baseX: c * spacingX + spacingX / 2,
                    baseY: r * spacingY + spacingY / 2,
                    x: 0,
                    y: 0,
                    phase: Math.random() * Math.PI * 2,
                    size: Math.random() * 1.5 + 0.5
                });
            }
        }
    };

    const animateLattice = () => {
        if (!canvas || !ctx) return;
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        
        const time = Date.now() * 0.002;
        
        // Render links between points to build mesh
        ctx.strokeStyle = 'rgba(72, 219, 251, 0.04)';
        ctx.lineWidth = 1;
        
        // Draw lattice dots and wave responses
        gridPoints.forEach((p, idx) => {
            // Swaying offset representing lattice perturbation noise (MLWE)
            const noiseX = Math.sin(time + p.phase) * 3;
            const noiseY = Math.cos(time + p.phase) * 3;
            p.x = p.baseX + noiseX;
            p.y = p.baseY + noiseY;

            ctx.fillStyle = 'rgba(72, 219, 251, 0.2)';
            
            // If encrypting shockwave is running
            if (isPulsing) {
                const dist = Math.hypot(p.x - canvas.width / 2, p.y - canvas.height / 2);
                if (Math.abs(dist - pulseWave) < 15) {
                    ctx.fillStyle = 'rgba(29, 209, 161, 0.8)';
                    p.x += Math.sin(dist) * 4;
                }
            }

            ctx.beginPath();
            ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
            ctx.fill();
        });

        // Draw structural vectors connecting random nodes
        ctx.strokeStyle = 'rgba(72, 219, 251, 0.15)';
        ctx.beginPath();
        for (let i = 0; i < gridPoints.length; i += 24) {
            if (gridPoints[i] && gridPoints[i+1]) {
                ctx.moveTo(gridPoints[i].x, gridPoints[i].y);
                ctx.lineTo(gridPoints[i+1].x, gridPoints[i+1].y);
            }
        }
        ctx.stroke();

        if (isPulsing) {
            pulseWave += 4;
            if (pulseWave > canvas.width) {
                isPulsing = false;
            }
        }

        animId = requestAnimationFrame(animateLattice);
    };

    // Entropy Slider value update
    const seedSlider = document.getElementById('quantum-seed-slider');
    const seedSliderVal = document.getElementById('seed-slider-val');
    if (seedSlider) {
        seedSlider.addEventListener('input', () => {
            seedSliderVal.textContent = `${seedSlider.value} bits`;
        });
    }

    // Keypair generation routine
    const btnGenKeys = document.getElementById('btn-quantum-genkeys');
    const pubKeyText = document.getElementById('txt-public-key');
    const privKeyText = document.getElementById('txt-private-key');

    if (btnGenKeys) {
        btnGenKeys.addEventListener('click', () => {
            pubKeyText.placeholder = "Generating illustrative sample text only...";
            privKeyText.placeholder = "Generating illustrative sample text only...";
            
            let progress = 0;
            const progressInterval = setInterval(() => {
                progress += 25;
                if (progress >= 100) {
                    clearInterval(progressInterval);
                    
                    // Synthesize robust hex key strings
                    const entropySeed = seedSlider ? seedSlider.value : 512;
                    const mockPub = generateMockHexBytes(160) + `\n[DEMO-STRING-NOT-A-KYBER-KEY-seed=${entropySeed}]`;
                    const mockPriv = generateMockHexBytes(120) + `\n[DEMO-STRING-NOT-A-PRIVATE-KEY]`;
                    
                    pubKeyText.value = mockPub;
                    privKeyText.value = mockPriv;
                    generatedKeys = true;
                    
                    window.addTimelineLog(`DEMO: Illustrative random strings generated with Math.random and parameter ${entropySeed}; no Kyber keypair or entropy source was used.`);
                    window.showStatusOverlay("Demo Strings Ready", "No cryptographic keypair or entropy source was generated.", 1000);
                }
            }, 100);
        });
    }

    // Data Encryption trigger
    const btnEncrypt = document.getElementById('btn-quantum-encrypt');
    const btnDecrypt = document.getElementById('btn-quantum-decrypt');
    const plainText = document.getElementById('txt-quantum-plain');
    const cipherText = document.getElementById('txt-quantum-cipher');

    if (btnEncrypt) {
        btnEncrypt.addEventListener('click', () => {
            const rawInput = plainText.value.trim();
            if (!rawInput) {
                alert("Please enter a cleartext payload to encrypt.");
                return;
            }
            if (!generatedKeys) {
                alert("Generate the illustrative demo strings before running the reversible demo transform.");
                return;
            }

            // Scramble lattice grid dots
            pulseWave = 0;
            isPulsing = true;

            // Illustrative reversible transform; this is not encryption.
            let cipherHex = "";
            for (let i = 0; i < rawInput.length; i++) {
                const asciiVal = rawInput.charCodeAt(i);
                // Multiplying by random polynomial noise coefficient mimicking MLWE error addition
                const scrambled = (asciiVal * 17 + 23) ^ 0xA5;
                cipherHex += scrambled.toString(16).padStart(4, '0').toUpperCase();
            }

            const header = `[SENTINEL-DEMO-NOT-SECURE]\n`;
            cipherText.value = header + chunkString(cipherHex, 8).join('-');
            window.addTimelineLog("DEMO: Reversible browser-only string transform; this is not encryption and must not be used to protect data.");
        });
    }

    if (btnDecrypt) {
        btnDecrypt.addEventListener('click', () => {
            const cipherData = cipherText.value.trim();
            if (!cipherData) {
                alert("No encrypted matrix packet found to solve.");
                return;
            }

            let hexPayload = cipherData.replace('[SENTINEL-DEMO-NOT-SECURE]\n', '').replace(/-/g, '');
            let decryptedStr = "";
            
            try {
                for (let i = 0; i < hexPayload.length; i += 4) {
                    const chunk = hexPayload.substring(i, i + 4);
                    const scrambledVal = parseInt(chunk, 16);
                    // Reverse the illustrative arithmetic transform; no lattice operation occurs.
                    const unscrambled = (scrambledVal ^ 0xA5);
                    const asciiVal = Math.round((unscrambled - 23) / 17);
                    decryptedStr += String.fromCharCode(asciiVal);
                }
                
                plainText.value = decryptedStr;
                window.addTimelineLog("DEMO: Reversed the illustrative string transform; no Kyber or lattice operation was performed.");
                window.showStatusOverlay("Demo Transform Reversed", "No cryptographic decryption was performed.", 1000);
            } catch (err) {
                alert("Failed to solve lattice vector. Cipher packet corrupted.");
            }
        });
    }

    // Helper functions
    const generateMockHexBytes = (count) => {
        let out = "";
        for (let i = 0; i < count; i++) {
            out += Math.floor(Math.random() * 256).toString(16).padStart(2, '0').toUpperCase();
            if (i > 0 && i % 16 === 15 && i < count - 1) out += "\n";
            else if (i < count - 1) out += " ";
        }
        return out;
    };

    const chunkString = (str, len) => {
        const size = Math.ceil(str.length / len);
        const r = new Array(size);
        let offset = 0;
        for (let i = 0; i < size; i++) {
            r[i] = str.substring(offset, offset + len);
            offset += len;
        }
        return r;
    };

})();

// --- SentinelOS Shadow313 Quantum Kernel & Satellite Uplink Module ---

document.addEventListener('DOMContentLoaded', () => {
    const satCanvas = document.getElementById('s313-sat-canvas');
    const chatScreen = document.getElementById('s313-chat-screen');
    const chatInput = document.getElementById('s313-chat-input');
    const btnSend = document.getElementById('btn-s313-send');
    const btnPing = document.getElementById('btn-s313-ping');
    const btnRecalibrate = document.getElementById('btn-s313-recalibrate');
    const backendSelect = document.getElementById('s313-backend-select');

    if (!satCanvas || !chatScreen) return;

    // ========================================================================
    // 1. SATELLITE CONSTELLATION CANVAS — Orbital visualization
    // ========================================================================
    const ctx = satCanvas.getContext('2d');
    let satellites = [];
    let beams = [];
    let animId = null;
    let canvasActive = false;

    const resizeCanvas = () => {
        const wrap = satCanvas.parentElement;
        satCanvas.width = wrap.clientWidth;
        satCanvas.height = wrap.clientHeight || 280;
    };

    class Satellite {
        constructor(idx) {
            this.idx = idx;
            this.angle = (Math.PI * 2 / 7) * idx + Math.random() * 0.3;
            this.orbitRx = satCanvas.width * 0.38 + Math.random() * 20;
            this.orbitRy = satCanvas.height * 0.32 + Math.random() * 10;
            this.speed = 0.003 + Math.random() * 0.002;
            this.size = 3 + Math.random() * 2;
            this.pulsePhase = Math.random() * Math.PI * 2;
            this.name = `SAT-${String(idx + 1).padStart(2, '0')}`;
            this.active = true;
        }
        update(t) {
            this.angle += this.speed;
            this.cx = satCanvas.width / 2;
            this.cy = satCanvas.height / 2;
            this.x = this.cx + Math.cos(this.angle) * this.orbitRx;
            this.y = this.cy + Math.sin(this.angle) * this.orbitRy * 0.6;
            this.pulsePhase += 0.05;
        }
        draw(ctx) {
            // Orbit path (faint)
            ctx.strokeStyle = 'rgba(123, 97, 255, 0.08)';
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.ellipse(this.cx, this.cy, this.orbitRx, this.orbitRy * 0.6, 0, 0, Math.PI * 2);
            ctx.stroke();

            if (!this.active) return;

            // Satellite glow
            const pulse = Math.sin(this.pulsePhase) * 0.3 + 0.7;
            const gradient = ctx.createRadialGradient(this.x, this.y, 0, this.x, this.y, this.size * 4);
            gradient.addColorStop(0, `rgba(123, 97, 255, ${0.6 * pulse})`);
            gradient.addColorStop(1, 'rgba(123, 97, 255, 0)');
            ctx.fillStyle = gradient;
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.size * 4, 0, Math.PI * 2);
            ctx.fill();

            // Satellite body
            ctx.fillStyle = `rgba(200, 180, 255, ${pulse})`;
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
            ctx.fill();

            // Solar panels
            ctx.strokeStyle = `rgba(123, 97, 255, ${0.7 * pulse})`;
            ctx.lineWidth = 1.5;
            ctx.beginPath();
            ctx.moveTo(this.x - this.size * 3, this.y);
            ctx.lineTo(this.x - this.size, this.y);
            ctx.moveTo(this.x + this.size, this.y);
            ctx.lineTo(this.x + this.size * 3, this.y);
            ctx.stroke();

            // Label
            ctx.fillStyle = `rgba(200, 200, 255, ${0.5 * pulse})`;
            ctx.font = '8px Orbitron, monospace';
            ctx.fillText(this.name, this.x - 14, this.y - this.size - 6);
        }
    }

    class UplinkBeam {
        constructor(sat) {
            this.sat = sat;
            this.progress = 0;
            this.active = true;
            this.speed = 0.02 + Math.random() * 0.01;
        }
        update() {
            this.progress += this.speed;
            if (this.progress > 1) {
                this.progress = 0;
            }
        }
        draw(ctx) {
            if (!this.sat.active) return;
            const groundX = satCanvas.width / 2;
            const groundY = satCanvas.height - 20;

            // Beam line
            const grad = ctx.createLinearGradient(groundX, groundY, this.sat.x, this.sat.y);
            grad.addColorStop(0, 'rgba(0, 212, 170, 0.5)');
            grad.addColorStop(0.5, 'rgba(123, 97, 255, 0.3)');
            grad.addColorStop(1, 'rgba(123, 97, 255, 0.05)');

            ctx.strokeStyle = grad;
            ctx.lineWidth = 1;
            ctx.setLineDash([3, 6]);
            ctx.beginPath();
            ctx.moveTo(groundX, groundY);
            ctx.lineTo(this.sat.x, this.sat.y);
            ctx.stroke();
            ctx.setLineDash([]);

            // Traveling packet
            const px = groundX + (this.sat.x - groundX) * this.progress;
            const py = groundY + (this.sat.y - groundY) * this.progress;
            ctx.fillStyle = `rgba(0, 212, 170, ${1 - this.progress})`;
            ctx.beginPath();
            ctx.arc(px, py, 2.5, 0, Math.PI * 2);
            ctx.fill();
        }
    }

    const initSatellites = () => {
        resizeCanvas();
        satellites = [];
        beams = [];
        for (let i = 0; i < 7; i++) {
            const sat = new Satellite(i);
            satellites.push(sat);
            beams.push(new UplinkBeam(sat));
        }
    };

    const drawGround = () => {
        const gx = satCanvas.width / 2;
        const gy = satCanvas.height - 20;

        // Ground station glow
        const grad = ctx.createRadialGradient(gx, gy, 0, gx, gy, 25);
        grad.addColorStop(0, 'rgba(0, 212, 170, 0.5)');
        grad.addColorStop(1, 'rgba(0, 212, 170, 0)');
        ctx.fillStyle = grad;
        ctx.beginPath();
        ctx.arc(gx, gy, 25, 0, Math.PI * 2);
        ctx.fill();

        // Station icon
        ctx.fillStyle = '#00d4aa';
        ctx.beginPath();
        ctx.arc(gx, gy, 5, 0, Math.PI * 2);
        ctx.fill();

        // Antenna lines
        ctx.strokeStyle = 'rgba(0, 212, 170, 0.6)';
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(gx, gy - 5);
        ctx.lineTo(gx, gy - 15);
        ctx.moveTo(gx - 8, gy - 12);
        ctx.lineTo(gx, gy - 15);
        ctx.lineTo(gx + 8, gy - 12);
        ctx.stroke();

        // Label
        ctx.fillStyle = 'rgba(0, 212, 170, 0.7)';
        ctx.font = '9px Orbitron, monospace';
        ctx.textAlign = 'center';
        ctx.fillText('SHADOW313 KERNEL', gx, gy + 16);
        ctx.textAlign = 'start';
    };

    const animateSatellites = () => {
        if (!canvasActive) return;
        ctx.clearRect(0, 0, satCanvas.width, satCanvas.height);

        // Starfield
        for (let i = 0; i < 60; i++) {
            const sx = (i * 37 + i * i * 7) % satCanvas.width;
            const sy = (i * 23 + i * i * 3) % satCanvas.height;
            const flicker = Math.sin(Date.now() * 0.001 + i) * 0.3 + 0.5;
            ctx.fillStyle = `rgba(200, 210, 240, ${flicker * 0.3})`;
            ctx.beginPath();
            ctx.arc(sx, sy, 0.8, 0, Math.PI * 2);
            ctx.fill();
        }

        drawGround();
        beams.forEach(b => { b.update(); b.draw(ctx); });
        satellites.forEach(s => { s.update(); s.draw(ctx); });

        animId = requestAnimationFrame(animateSatellites);
    };

    // Init handler
    window.initShadow313View = () => {
        canvasActive = true;
        initSatellites();
        if (!animId) animateSatellites();
        startTemporalBinding();
        startMetricsLoop();
    };

    // Cleanup when leaving view
    const stopSatelliteAnim = () => {
        canvasActive = false;
        if (animId) {
            cancelAnimationFrame(animId);
            animId = null;
        }
    };

    // ========================================================================
    // 2. 313 TEMPORAL BINDING PROTOCOL
    // ========================================================================
    const bindTsEl = document.getElementById('s313-bind-ts');
    const bindHashEl = document.getElementById('s313-bind-hash');
    const bindCountEl = document.getElementById('s313-bind-count');
    const temporalNum = document.getElementById('s313-temporal-num');
    let bindCount = 0;
    let temporalInterval = null;

    // Simple SHA-3-like hash simulation (display-only)
    const simHash = (input) => {
        let hash = 0x313313;
        for (let i = 0; i < input.length; i++) {
            hash = ((hash << 5) - hash + input.charCodeAt(i)) | 0;
            hash = hash ^ (hash >>> 13);
            hash = (hash * 0x5bd1e995) | 0;
        }
        const hex = Math.abs(hash).toString(16).padStart(8, '0');
        // Generate a longer hash-like string
        let result = '';
        for (let j = 0; j < 8; j++) {
            const segment = Math.abs((hash * (j + 1) * 0x1337) ^ (hash >>> j)).toString(16).padStart(8, '0');
            result += segment;
        }
        return result.slice(0, 64);
    };

    const performTemporalBind = () => {
        const now = Date.now();
        const nsStr = `${now}000313`; // Simulate nanosecond ending in 313
        const payload = `shadow313_kernel_${now}`;
        const hash = simHash(payload + nsStr);

        bindCount++;
        if (bindTsEl) bindTsEl.textContent = nsStr;
        if (bindHashEl) bindHashEl.textContent = hash.slice(0, 16) + '...' + hash.slice(-8);
        if (bindCountEl) bindCountEl.textContent = bindCount.toLocaleString();

        // Pulse the 313 number
        if (temporalNum) {
            temporalNum.classList.add('pulse-active');
            setTimeout(() => temporalNum.classList.remove('pulse-active'), 300);
        }
    };

    const startTemporalBinding = () => {
        if (temporalInterval) clearInterval(temporalInterval);
        temporalInterval = setInterval(performTemporalBind, 1500);
        performTemporalBind();
    };

    // ========================================================================
    // 3. SATELLITE METRICS FLUCTUATION
    // ========================================================================
    const elLatency = document.getElementById('s313-latency');
    const elSignal = document.getElementById('s313-signal');
    const elBandwidth = document.getElementById('s313-bandwidth');
    const elActiveSats = document.getElementById('s313-active-sats');
    const elTpFill = document.getElementById('s313-tp-fill');
    const elTpVal = document.getElementById('s313-tp-val');
    let metricsInterval = null;

    const startMetricsLoop = () => {
        if (metricsInterval) clearInterval(metricsInterval);
        metricsInterval = setInterval(() => {
            const lat = (35 + Math.random() * 20).toFixed(0);
            const sig = (-60 - Math.random() * 15).toFixed(0);
            const bw = (2.0 + Math.random() * 1.2).toFixed(1);
            const tp = (70 + Math.random() * 25).toFixed(0);

            if (elLatency) elLatency.textContent = `${lat}ms`;
            if (elSignal) elSignal.textContent = `${sig} dBm`;
            if (elBandwidth) elBandwidth.textContent = `${bw} Gbps`;
            if (elTpFill) elTpFill.style.width = `${tp}%`;
            if (elTpVal) elTpVal.textContent = `${tp}%`;
        }, 3000);
    };

    // ========================================================================
    // 4. PING & RECALIBRATE BUTTONS
    // ========================================================================
    if (btnPing) {
        btnPing.addEventListener('click', () => {
            btnPing.disabled = true;
            const uplinkDot = document.getElementById('s313-uplink-dot');
            const uplinkStatus = document.getElementById('s313-uplink-status');

            if (uplinkStatus) uplinkStatus.textContent = 'PINGING CONSTELLATION...';
            if (uplinkDot) uplinkDot.classList.add('pinging');

            addChatMsg('system', '⬡ Transmitting ping to satellite constellation via middleware bridge...');

            if (window.showStatusOverlay) {
                window.showStatusOverlay('Ping Constellation', 'Sending QKD-TLS handshake to 7 orbital nodes...', 2000);
            }

            // Simulate sequential ping responses
            let pinged = 0;
            const pingInterval = setInterval(() => {
                if (pinged < 7) {
                    const latency = (30 + Math.random() * 25).toFixed(1);
                    addChatMsg('system', `  ↳ SAT-${String(pinged + 1).padStart(2, '0')} responded: ${latency}ms RTT | Signal OK`);
                    pinged++;
                } else {
                    clearInterval(pingInterval);
                    if (uplinkStatus) uplinkStatus.textContent = 'UPLINK ACTIVE';
                    if (uplinkDot) uplinkDot.classList.remove('pinging');
                    btnPing.disabled = false;
                    addChatMsg('system', '⬡ Constellation ping complete. All 7 nodes responding normally.');

                    if (window.addTimelineLog) {
                        window.addTimelineLog('SHADOW313: Satellite constellation ping completed — all nodes healthy.');
                    }
                }
            }, 400);
        });
    }

    if (btnRecalibrate) {
        btnRecalibrate.addEventListener('click', () => {
            btnRecalibrate.disabled = true;
            addChatMsg('system', '⬡ Recalibrating orbital tracking parameters...');

            if (window.showStatusOverlay) {
                window.showStatusOverlay('Recalibrating', 'Adjusting antenna gain and Doppler compensation...', 1800);
            }

            // Refresh satellite positions
            initSatellites();

            setTimeout(() => {
                const coordEl = document.getElementById('s313-coord');
                const lat = (40 + Math.random() * 5).toFixed(3);
                const lon = (-80 - Math.random() * 10).toFixed(3);
                const alt = (500 + Math.random() * 100).toFixed(0);
                if (coordEl) coordEl.textContent = `LAT ${lat} · LON ${lon} · ALT ${alt}km`;

                addChatMsg('system', `⬡ Recalibration complete. New tracking: LAT ${lat}, LON ${lon}, ALT ${alt}km`);
                btnRecalibrate.disabled = false;

                if (window.addTimelineLog) {
                    window.addTimelineLog(`SHADOW313: Orbital recalibration done. Updated ephemeris data for constellation.`);
                }
            }, 2000);
        });
    }

    // ========================================================================
    // 5. CIRCUIT PROFILER — Backend switching & QASM/Qiskit Exporter
    // ========================================================================
    const profilerData = {
        local_sim: { qubits: [4, 65], depth: [12, 50], q1: [28, 100], q2: [8, 40] },
        fake_ibm: { qubits: [5, 65], depth: [18, 50], q1: [42, 100], q2: [14, 40] }
    };

    const circuitCodes = {
        bell_state: {
            qiskit: `from qiskit import QuantumCircuit, Aer, execute\n\n# Create a Bell State circuit\nqc = QuantumCircuit(2, 2)\nqc.h(0)\nqc.cx(0, 1)\nqc.measure([0, 1], [0, 1])\n\n# Execute locally using Aer simulator\nbackend = Aer.get_backend('qasm_simulator')\njob = execute(qc, backend, shots=1024)\nresult = job.result()\ncounts = result.get_counts(qc)\nprint("Counts:", counts)`,
            qasm: `OPENQASM 2.0;\ninclude "qelib1.inc";\nqreg q[2];\ncreg c[2];\nh q[0];\ncx q[0],q[1];\nmeasure q -> c;`
        },
        shors_15: {
            qiskit: `from qiskit import QuantumCircuit, Aer, execute\nimport numpy as np\n\n# Shor's period-finding circuit approximation (N=15, a=7)\nqc = QuantumCircuit(4, 4)\nqc.h(range(4))\n\n# Controlled modular multiplication\nqc.x(3)\nqc.cx(0, 1)\nqc.cx(1, 2)\nqc.cx(2, 3)\n\n# Quantum Fourier Transform inverse\n# (Simplified representation for 4 qubits)\nqc.h(0)\nqc.cp(np.pi/2, 1, 0)\nqc.h(1)\nqc.cp(np.pi/4, 2, 0)\n\nqc.measure(range(4), range(4))\nbackend = Aer.get_backend('qasm_simulator')\njob = execute(qc, backend, shots=2048)\nresult = job.result()\nprint("Shor factorization counts:", result.get_counts(qc))`,
            qasm: `OPENQASM 2.0;\ninclude "qelib1.inc";\nqreg q[4];\ncreg c[4];\nh q[0];\nh q[1];\nh q[2];\nh q[3];\nx q[3];\ncx q[0],q[1];\ncx q[1],q[2];\ncx q[2],q[3];\nmeasure q -> c;`
        },
        grovers_search: {
            qiskit: `from qiskit import QuantumCircuit, Aer, execute\n\n# 2-qubit Grover's Search circuit\nqc = QuantumCircuit(2, 2)\nqc.h([0, 1])\n\n# Oracle for state |11>\nqc.cz(0, 1)\n\n# Diffusion operator\nqc.h([0, 1])\nqc.x([0, 1])\nqc.cz(0, 1)\nqc.x([0, 1])\nqc.h([0, 1])\n\nqc.measure([0, 1], [0, 1])\nbackend = Aer.get_backend('qasm_simulator')\njob = execute(qc, backend, shots=1024)\nresult = job.result()\nprint("Grover search counts:", result.get_counts(qc))`,
            qasm: `OPENQASM 2.0;\ninclude "qelib1.inc";\nqreg q[2];\ncreg c[2];\nh q[0];\nh q[1];\ncz q[0],q[1];\nh q[0];\nh q[1];\nmeasure q -> c;`
        }
    };

    let activeCircuit = "bell_state";
    let activeTab = "qiskit";

    const updateCodeExporterUI = () => {
        const codeTextarea = document.getElementById('txt-s313-code');
        if (!codeTextarea) return;
        const currentCircuit = circuitCodes[activeCircuit];
        if (currentCircuit) {
            codeTextarea.value = currentCircuit[activeTab] || "";
        }
    };

    const fetchCircuitQasm = async (circuitName) => {
        try {
            // Attempt to dynamically fetch OpenQASM file from tracked assets
            const response = await fetch(`/shadow313/assets/circuits/${circuitName}.qasm`);
            if (response.ok) {
                const qasmText = await response.text();
                circuitCodes[circuitName].qasm = qasmText;
                updateCodeExporterUI();
                console.log(`Successfully fetched dynamic QASM asset: ${circuitName}.qasm`);
            }
        } catch (err) {
            console.warn(`Dynamic QASM fetch failed, using local fallback:`, err);
        }
    };

    // Tabs logic for code exporter
    const btnTabQiskit = document.getElementById('btn-tab-qiskit');
    const btnTabQasm = document.getElementById('btn-tab-qasm');

    if (btnTabQiskit && btnTabQasm) {
        btnTabQiskit.addEventListener('click', () => {
            btnTabQiskit.classList.add('active');
            btnTabQasm.classList.remove('active');
            activeTab = "qiskit";
            updateCodeExporterUI();
        });
        btnTabQasm.addEventListener('click', () => {
            btnTabQasm.classList.add('active');
            btnTabQiskit.classList.remove('active');
            activeTab = "qasm";
            updateCodeExporterUI();
        });
    }

    const copyBtn = document.getElementById('btn-s313-copy-code');
    if (copyBtn) {
        copyBtn.addEventListener('click', () => {
            const codeTextarea = document.getElementById('txt-s313-code');
            if (codeTextarea && codeTextarea.value) {
                navigator.clipboard.writeText(codeTextarea.value).then(() => {
                    if (window.showStatusOverlay) {
                        window.showStatusOverlay("Code Copied", "Quantum circuit code successfully copied to clipboard!", 1200);
                    } else {
                        alert("Code copied successfully!");
                    }
                });
            }
        });
    }

    if (backendSelect) {
        backendSelect.addEventListener('change', () => {
            const profile = profilerData[backendSelect.value] || profilerData.local_sim;
            updateProfiler(profile);
            addChatMsg('system', `⬡ Backend switched to: ${backendSelect.value}`);
        });
    }

    const updateProfiler = (profile) => {
        const animate = (id, valId, data) => {
            const bar = document.getElementById(id);
            const val = document.getElementById(valId);
            if (bar) bar.style.width = `${(data[0] / data[1]) * 100}%`;
            if (val) val.textContent = data[0];
        };
        animate('s313-prof-qubits', 's313-prof-qubits-val', profile.qubits);
        animate('s313-prof-depth', 's313-prof-depth-val', profile.depth);
        animate('s313-prof-1q', 's313-prof-1q-val', profile.q1);
        animate('s313-prof-2q', 's313-prof-2q-val', profile.q2);
    };

    // Load initial code exporter values and trigger fetch
    updateCodeExporterUI();
    fetchCircuitQasm('bell_state');
    fetchCircuitQasm('shors_15');
    fetchCircuitQasm('grovers_search');

    // ========================================================================
    // 6. QUANTUM CHAT TERMINAL — Thought Engine
    // ========================================================================
    const chatResponses = {
        factor: {
            category: 'math/shor',
            respond: (input) => {
                const num = parseInt(input.match(/\d+/)?.[0] || '15');
                const factors = [];
                for (let i = 2; i <= Math.sqrt(num); i++) {
                    if (num % i === 0) factors.push([i, num / i]);
                }
                if (factors.length === 0) return `⬡ [Shor Demo] ${num} appears to be prime. No non-trivial factors found via quantum period-finding.`;
                const [a, b] = factors[0];
                return `⬡ [Shor Demo] Quantum period-finding on N=${num}:\n  Factors discovered: ${a} × ${b} = ${num}\n  Circuit: 4 qubits, depth 12 | 313-bound signature attached.`;
            }
        },
        find: {
            category: 'search/grover',
            respond: () => `⬡ [Grover Demo] Amplitude amplification search:\n  Target found in √N iterations (2 iterations for 4-item space)\n  Probability of correct result: 97.2%\n  Circuit profiled: 2 qubits, depth 8, 6 1Q gates, 2 2Q gates.`
        },
        random: {
            category: 'random/qrng',
            respond: () => {
                const bits = Array.from({length: 16}, () => Math.random() > 0.5 ? '1' : '0').join('');
                const hex = parseInt(bits, 2).toString(16).padStart(4, '0');
                return `⬡ [QRNG] Quantum random bits generated:\n  Binary: ${bits}\n  Hex: 0x${hex}\n  Source: Hadamard + measurement on 16-qubit register.`;
            }
        },
        superposition: {
            category: 'quantum/explain',
            respond: () => `⬡ [Quantum] Superposition is the principle that a quantum bit (qubit) can exist in a combination of |0⟩ and |1⟩ states simultaneously:\n  |ψ⟩ = α|0⟩ + β|1⟩ where |α|² + |β|² = 1\n  Upon measurement, the qubit collapses to one definite state with probability |α|² or |β|².`
        },
        entanglement: {
            category: 'quantum/explain',
            respond: () => `⬡ [Quantum] Entanglement is a correlation between qubits where the state of one instantaneously influences the other:\n  Bell state: |Φ+⟩ = (|00⟩ + |11⟩)/√2\n  Measuring one qubit as |0⟩ guarantees the other is |0⟩, regardless of distance.`
        },
        status: {
            category: 'system',
            respond: () => `⬡ [Shadow313 Status]\n  Temporal Binds: ${bindCount} | Q-Runs: ${Math.floor(bindCount * 0.3)} | Backend: ${backendSelect?.value || 'local_sim'}\n  Satellites: 7/7 ONLINE | Middleware: ROUTING | Kernel: ACTIVE`
        },
        satellite: {
            category: 'system/uplink',
            respond: () => {
                const sats = satellites.filter(s => s.active).length;
                return `⬡ [Constellation Report]\n  Active satellites: ${sats}/7\n  Avg latency: ${(35 + Math.random() * 15).toFixed(1)}ms\n  Signal strength: ${(-60 - Math.random() * 10).toFixed(0)} dBm\n  Uplink encrypted via QKD-TLS through middleware bridge.`;
            }
        }
    };

    const classifyQuestion = (input) => {
        const lower = input.toLowerCase();
        if (/factor\s*\d+/.test(lower)) {
            activeCircuit = "shors_15";
            updateCodeExporterUI();
            return 'factor';
        }
        if (/find|search|grover/.test(lower)) {
            activeCircuit = "grovers_search";
            updateCodeExporterUI();
            return 'find';
        }
        if (/random|predict|qrng|dice/.test(lower)) {
            activeCircuit = "bell_state";
            updateCodeExporterUI();
            return 'random';
        }
        if (/superposition/.test(lower)) return 'superposition';
        if (/entangle/.test(lower)) return 'entanglement';
        if (/status/.test(lower)) return 'status';
        if (/satellite|uplink|constellation/.test(lower)) return 'satellite';
        return null;
    };

    const escapeHtml = (value) => String(value).replace(/[&<>'"]/g, ch => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        "'": '&#39;',
        '"': '&quot;'
    }[ch]));

    const addChatMsg = (type, text) => {
        const div = document.createElement('div');
        div.className = `s313-chat-msg ${type}`;
        // Preserve newlines without allowing user-provided HTML injection.
        div.innerHTML = escapeHtml(text).replace(/\n/g, '<br>');
        chatScreen.appendChild(div);
        chatScreen.scrollTop = chatScreen.scrollHeight;
    };

    const fetchAiResponse = async (input) => {
        const response = await fetch('/api/chat', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ message: input })
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok || !data.reply) throw new Error(data.error || 'AI Gateway request failed');
        return data.reply;
    };

    const handleChatInput = () => {
        const input = chatInput.value.trim();
        if (!input) return;

        addChatMsg('user', `> ${input}`);
        chatInput.value = '';

        const category = classifyQuestion(input);

        setTimeout(async () => {
            try {
                addChatMsg('system', '[ai-gateway] routing request');
                const reply = await fetchAiResponse(input);
                addChatMsg('response', reply);
            } catch (error) {
                console.warn('AI Gateway unavailable, using local Shadow313 fallback', error);
                if (category && chatResponses[category]) {
                    const resp = chatResponses[category];
                    addChatMsg('system', `[${resp.category}] classified locally`);
                    addChatMsg('response', `${resp.respond(input)}

[Local fallback: AI Gateway is unavailable or not configured.]`);
                } else {
                    addChatMsg('response', `⬡ [general] I processed your query "${input}" through the local thought engine.
  Current backend: ${backendSelect?.value || 'local_sim'}
  [Local fallback: AI Gateway is unavailable or not configured.]`);
                }
            } finally {
                performTemporalBind();
                addChatMsg('system', `  ↳ 313-bound temporal signature: ${simHash(input).slice(0, 24)}...`);
            }
        }, 200);
    };


    if (btnSend) {
        btnSend.addEventListener('click', handleChatInput);
    }
    if (chatInput) {
        chatInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') handleChatInput();
        });
    }

    // ========================================================================
    // 7. MIDDLEWARE BEAM ANIMATIONS
    // ========================================================================
    const beam1 = document.getElementById('s313-beam-1');
    const beam2 = document.getElementById('s313-beam-2');
    let beamPhase = 0;

    setInterval(() => {
        beamPhase = (beamPhase + 1) % 100;
        if (beam1) beam1.style.backgroundPosition = `${beamPhase * 3}px 0`;
        if (beam2) beam2.style.backgroundPosition = `${beamPhase * 3}px 0`;
    }, 50);

    // ========================================================================
    // 8. REGISTER WITH APP.JS VIEW INIT SYSTEM
    // ========================================================================
    // The view init is triggered from app.js triggerViewInit
    window.initShadow313View = window.initShadow313View || (() => {});

    // Handle window resize
    window.addEventListener('resize', () => {
        if (canvasActive) resizeCanvas();
    });

    // Auto-init if the view is already visible
    const s313View = document.getElementById('view-shadow313');
    if (s313View && s313View.classList.contains('active')) {
        window.initShadow313View();
    }
});

// --- SENTINELOS Core Shell Controller ---

document.addEventListener('DOMContentLoaded', () => {
    // 1. Loading Screen Sequence
    const loadingScreen = document.getElementById('loading-screen');
    const loadingText = document.getElementById('loading-text');
    
    const loadingPhrases = [
        "ESTABLISHING SECURE PROTOCOLS...",
        "DECRYPTING BLOCKCHAIN FORENSICS...",
        "ROTATING QUANTUM ENTROPY SEEDS...",
        "SYNCHRONIZING AI THREAT CORE...",
        "ACCESS GRANTED. INITIALIZING SHELL..."
    ];
    
    let phraseIdx = 0;
    const phraseInterval = setInterval(() => {
        if (phraseIdx < loadingPhrases.length - 1) {
            phraseIdx++;
            loadingText.textContent = loadingPhrases[phraseIdx];
        }
    }, 300);

    setTimeout(() => {
        clearInterval(phraseInterval);
        loadingScreen.classList.add('hidden');
    }, 1500);

    // 2. Navigation Routing & View Switching
    const navItems = document.querySelectorAll('.nav-item');
    const viewPanes = document.querySelectorAll('.view-pane');

    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const targetView = item.getAttribute('data-view');
            
            // Toggle active nav class
            navItems.forEach(nav => nav.classList.remove('active'));
            item.classList.add('active');
            
            // Toggle active view pane
            viewPanes.forEach(pane => pane.classList.remove('active'));
            const targetPane = document.getElementById(`view-${targetView}`);
            if (targetPane) {
                targetPane.classList.add('active');
                
                // Initialize specific views if needed
                triggerViewInit(targetView);
            }
        });
    });

    // Hash router fallback for direct navigation
    const checkHash = () => {
        const hash = window.location.hash.substring(1);
        if (hash) {
            const matchingNav = document.querySelector(`.nav-item[data-view="${hash}"]`);
            if (matchingNav) matchingNav.click();
        }
    };
    window.addEventListener('hashchange', checkHash);
    setTimeout(checkHash, 100);

    // 3. Fluctuating Telemetry Metric Loops
    const metricAi = document.getElementById('metric-ai');
    const metricEntropy = document.getElementById('metric-entropy');
    const metricBlocks = document.getElementById('metric-blocks');
    const metricNetwork = document.getElementById('metric-network');
    const miningStatus = document.getElementById('mining-status');

    let currentBlock = 74902;
    let netThroughput = 1.2;

    setInterval(() => {
        // AI score fluctuations
        const aiScore = (98.0 + Math.random() * 0.8).toFixed(2);
        metricAi.textContent = `${aiScore}%`;
        
        // Quantum frequency shifts
        const entropyFreq = (4.75 + Math.random() * 0.25).toFixed(2);
        metricEntropy.textContent = `${entropyFreq} GHz`;
        
        // Network speed throughput
        netThroughput = (1.1 + Math.random() * 0.3).toFixed(2);
        metricNetwork.textContent = `${netThroughput} Gbps`;
    }, 3000);

    // Simulate mining ledger blocks
    setInterval(() => {
        currentBlock++;
        metricBlocks.textContent = `#${currentBlock.toLocaleString()}`;
        miningStatus.textContent = "SEALED";
        miningStatus.classList.remove('up');
        miningStatus.classList.add('text-glow');
        
        addTimelineLog(`Block #${currentBlock} mined & sealed. Verified forensic evidence integrity. Hash index written.`);

        setTimeout(() => {
            miningStatus.textContent = "MINING";
            miningStatus.classList.add('up');
            miningStatus.classList.remove('text-glow');
        }, 1500);
    }, 12000);

    // 4. Global Alarm Banner Ticker Alerts Rotation
    const tickerText = document.getElementById('global-ticker');
    const alertSystemPhrases = [
        "Lattice-cryptography key rotation committed to ledger block.",
        "Warning: Simulated DDoS probe on Subnet B-7 trapped in honeypot.",
        "AI Engine predicted ransomware footprint vectors; playbook isolation armed.",
        "Malware AI disassembly reports completed for host logs extraction payload.",
        "Zero-Knowledge node authorization completed for external gateway sync.",
        "SentinelOS core systems healthy. Lattice encryption nodes immune to Shor calculations."
    ];

    setInterval(() => {
        const randAlert = alertSystemPhrases[Math.floor(Math.random() * alertSystemPhrases.length)];
        tickerText.textContent = `SYSTEM LOG: ${randAlert}`;
    }, 8000);

    // 5. Dynamic Background Canvas: Particle Matrix
    const heroCanvas = document.getElementById('hero-particles-canvas');
    if (heroCanvas) {
        const ctx = heroCanvas.getContext('2d');
        let particles = [];
        
        const resizeCanvas = () => {
            const rect = heroCanvas.parentElement.getBoundingClientRect();
            heroCanvas.width = rect.width;
            heroCanvas.height = rect.height || 180;
        };
        resizeCanvas();
        window.addEventListener('resize', resizeCanvas);

        class Particle {
            constructor() {
                this.x = Math.random() * heroCanvas.width;
                this.y = Math.random() * heroCanvas.height;
                this.size = Math.random() * 2 + 1;
                this.speedX = Math.random() * 0.4 - 0.2;
                this.speedY = Math.random() * 0.4 - 0.2;
                this.color = Math.random() > 0.5 ? '#48dbfb' : '#9b51e0';
            }
            update() {
                this.x += this.speedX;
                this.y += this.speedY;
                if (this.x < 0 || this.x > heroCanvas.width) this.speedX *= -1;
                if (this.y < 0 || this.y > heroCanvas.height) this.speedY *= -1;
            }
            draw() {
                ctx.fillStyle = this.color;
                ctx.beginPath();
                ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
                ctx.fill();
            }
        }

        for (let i = 0; i < 40; i++) {
            particles.push(new Particle());
        }

        const animate = () => {
            ctx.clearRect(0, 0, heroCanvas.width, heroCanvas.height);
            particles.forEach(p => {
                p.update();
                p.draw();
            });
            requestAnimationFrame(animate);
        };
        animate();
    }

    // 6. Biometric Fingerprint Scanner Interactions
    const btnScan = document.getElementById('btn-biometric-scan');
    const btnReset = document.getElementById('btn-biometric-reset');
    const bioScanner = document.querySelector('.biometric-scanner');
    const bioIndicator = document.getElementById('bio-indicator');
    const bioStatusText = document.getElementById('bio-status-text');
    const fpOuter = document.querySelector('.fp-outer');
    const fpMiddle = document.querySelector('.fp-middle');
    const fpInner = document.querySelector('.fp-inner');

    if (btnScan) {
        btnScan.addEventListener('click', () => {
            bioScanner.classList.add('scanning');
            bioIndicator.className = "biometric-indicator pending";
            bioStatusText.textContent = "SCANNING...";
            fpOuter.style.stroke = "var(--warning)";
            fpMiddle.style.stroke = "var(--warning)";
            fpInner.style.stroke = "var(--warning)";

            setTimeout(() => {
                bioScanner.classList.remove('scanning');
                bioIndicator.className = "biometric-indicator";
                bioStatusText.textContent = "ACCESS GRANTED";
                fpOuter.style.stroke = "var(--success)";
                fpMiddle.style.stroke = "var(--success)";
                fpInner.style.stroke = "var(--success)";
                
                addTimelineLog("Biometric fingerprint verification succeeded. Platform clearance level 5 rotated.");
                
                // Show modal overlay success confirmation
                showStatusOverlay("Biometric Authed", "Full Quantum Access clearance granted. Syncing secure ledger...", 1200);
            }, 2000);
        });
    }

    if (btnReset) {
        btnReset.addEventListener('click', () => {
            bioIndicator.className = "biometric-indicator locked";
            bioStatusText.textContent = "CLEARANCE REVOKED";
            fpOuter.style.stroke = "var(--danger)";
            fpMiddle.style.stroke = "var(--danger)";
            fpInner.style.stroke = "var(--danger)";
            
            addTimelineLog("Warning: Administrative clearance keys manually revoked. Re-auth required.");
        });
    }

    // 7. General Shared Helpers & Core View Initializer bindings
    window.addTimelineLog = (text) => {
        const timeline = document.querySelector('.timeline-container');
        if (timeline) {
            const time = new Date().toLocaleTimeString('en-US', { hour12: false });
            
            const logItem = document.createElement('div');
            logItem.className = 'timeline-item';

            const timeEl = document.createElement('div');
            timeEl.className = 'timeline-time';
            timeEl.textContent = time;

            const contentEl = document.createElement('div');
            contentEl.className = 'timeline-content';
            contentEl.textContent = text;

            logItem.appendChild(timeEl);
            logItem.appendChild(contentEl);
            timeline.insertBefore(logItem, timeline.firstChild);
            
            // Keep maximum 8 elements in logs to preserve memory
            if (timeline.children.length > 8) {
                timeline.removeChild(timeline.lastChild);
            }
        }
    };

    window.showStatusOverlay = (title, desc, duration = 1500) => {
        const overlay = document.getElementById('status-overlay');
        const overlayTitle = document.getElementById('status-overlay-title');
        const overlayDesc = document.getElementById('status-overlay-desc');
        
        if (overlay) {
            overlayTitle.textContent = title;
            overlayDesc.textContent = desc;
            overlay.style.display = 'flex';
            
            setTimeout(() => {
                overlay.style.display = 'none';
            }, duration);
        }
    };

    // Callback routers to dispatch init routines for different views
    const triggerViewInit = (viewName) => {
        const dispatches = {
            'quantum': () => window.initQuantumView && window.initQuantumView(),
            'threat': () => window.initThreatView && window.initThreatView(),
            'zkp': () => window.initZkpView && window.initZkpView(),
            'workspace': () => window.initWorkspaceView && window.initWorkspaceView(),
            'chaos': () => window.initChaosView && window.initChaosView(),
            'deception': () => window.initDeceptionView && window.initDeceptionView(),
            'sandbox': () => window.initSandboxView && window.initSandboxView(),
            'shadow313': () => window.initShadow313View && window.initShadow313View(),
            'pqc': () => window.initPqcView && window.initPqcView(),
            'swarm': () => window.initSwarmView && window.initSwarmView(),
            'deepfake': () => window.initDeepfakeView && window.initDeepfakeView(),
            'rf': () => window.initRfView && window.initRfView(),
            'ztna': () => window.initZtnaView && window.initZtnaView()
        };
        if (dispatches[viewName]) {
            dispatches[viewName]();
        }
    };

    // Overview Stats counter tracker simulator
    let activeThreats = 0;
    const countThreatsVal = document.getElementById('stat-threats');
    
    window.updateActiveThreatsCount = (delta) => {
        activeThreats = Math.max(0, activeThreats + delta);
        if (countThreatsVal) {
            countThreatsVal.textContent = activeThreats;
        }
    };

});

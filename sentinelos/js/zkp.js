// --- SENTINELOS Zero-Knowledge Proof System Module ---

(() => {
    const btnZkpInit = document.getElementById('btn-zkp-initiate');
    const secretInput = document.getElementById('zkp-secret-input');
    const curveSelect = document.getElementById('zkp-curve');
    const logBox = document.getElementById('zkp-output-logs');
    const verifBadge = document.getElementById('zkp-verif-badge');
    const verifBadgeText = document.getElementById('zkp-verif-badge-text');
    
    const actorProver = document.getElementById('actor-prover');
    const actorVerifier = document.getElementById('actor-verifier');
    const beamPath = document.querySelector('.nodes-handshake-wrapper');
    const zkpTabContent = document.getElementById('zkp-panel-content');

    window.initZkpView = () => {
        // Tab switching logic for ZKP Panel
        const tabs = document.querySelectorAll('.zkp-tab');
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                tabs.forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                
                const tabType = tab.getAttribute('data-tab');
                renderZkpTabContent(tabType);
            });
        });
    };

    const renderZkpTabContent = (type) => {
        if (!zkpTabContent) return;
        if (type === 'active-proofs') {
            zkpTabContent.innerHTML = `
                <div class="zkp-proof">
                    <div class="zkp-proof-header">
                        <span class="zkp-proof-title">Auth Token: ZK-AUTH-7412</span>
                        <span class="zkp-proof-status status-verified">VERIFIED</span>
                    </div>
                    <div class="zkp-proof-details">
                        <div class="zkp-detail"><span class="zkp-detail-label">Hash:</span><span class="zkp-detail-value">9f8e...3c2a</span></div>
                        <div class="zkp-detail"><span class="zkp-detail-label">Curve:</span><span class="zkp-detail-value">BLS12-381</span></div>
                        <div class="zkp-detail"><span class="zkp-detail-label">Entropy:</span><span class="zkp-detail-value">256-bit</span></div>
                        <div class="zkp-detail"><span class="zkp-detail-label">Latency:</span><span class="zkp-detail-value">0.12ms</span></div>
                    </div>
                </div>
                <div class="zkp-proof">
                    <div class="zkp-proof-header">
                        <span class="zkp-proof-title">Node Handshake: CL-AUTH-909</span>
                        <span class="zkp-proof-status status-pending">PENDING</span>
                    </div>
                    <div class="zkp-proof-details">
                        <div class="zkp-detail"><span class="zkp-detail-label">Hash:</span><span class="zkp-detail-value">bc2d...ef98</span></div>
                        <div class="zkp-detail"><span class="zkp-detail-label">Curve:</span><span class="zkp-detail-value">BN254</span></div>
                    </div>
                </div>
            `;
        } else {
            zkpTabContent.innerHTML = `
                <div class="zkp-proof" style="font-family: 'Fira Code', monospace; font-size:11px; line-height: 1.6;">
                    <div style="color: var(--accent); margin-bottom: 6px; font-weight: bold;">[BLS12-381 Generator parameters]</div>
                    <div>Curve: y² = x³ + 4</div>
                    <div>Field Size q: 381 bits</div>
                    <div>Group Order r: 255 bits (prime order)</div>
                    <div>Embedding Degree k: 12</div>
                    <div style="margin-top: 10px; color: var(--ai-purple); font-weight: bold;">[BN254 Generator parameters]</div>
                    <div>Curve: y² = x³ + 3</div>
                    <div>Field Size q: 254 bits</div>
                </div>
            `;
        }
    };

    if (btnZkpInit) {
        btnZkpInit.addEventListener('click', () => {
            const secretText = secretInput.value.trim();
            const selectedCurve = curveSelect.value;
            
            if (!secretText) {
                alert("Please enter a prover's secret passcode.");
                return;
            }

            // Hide previous badges and reset logs
            verifBadge.style.display = 'none';
            logBox.innerHTML = "";
            
            appendZkpLog("system", `[ZKP Setup] Initializing proving bounds for curve option: [${selectedCurve.toUpperCase()}]`);

            // Start step-by-step timed ZK-Snarks prover/verifier interaction logs
            setTimeout(() => {
                appendZkpLog("prover", `[Prover Setup] Hashing passcode into scalar integer field element s.`);
                appendZkpLog("prover", `[Prover Math] Computed commitment point C = g^s * h^r = 7F8B2...D41A`);
                actorProver.querySelector('.actor-status').textContent = "Commitment Created";
                actorProver.querySelector('.actor-status').style.color = "var(--accent)";
            }, 300);

            // Phase 2: Send commitment across channel beam
            setTimeout(() => {
                appendZkpLog("system", `[Channel] Transmitting commitment point C to Verifier node...`);
                beamPath.classList.add('sending-beam');
            }, 800);

            // Phase 3: Verifier receives commitment, registers listening, and sends challenges
            setTimeout(() => {
                beamPath.classList.remove('sending-beam');
                appendZkpLog("verifier", `[Verifier Node] Commitment received. Generating random binary query challenge challenge c = 1.`);
                actorVerifier.querySelector('.actor-status').textContent = "Challenge Fired";
                actorVerifier.querySelector('.actor-status').style.color = "var(--ai-purple)";
            }, 1800);

            // Phase 4: Prover computes ZK Proof Response
            setTimeout(() => {
                appendZkpLog("prover", `[Prover Math] Solving zero-knowledge polynomial challenge proof response vector: z = r + c * s.`);
                appendZkpLog("prover", `[Prover Setup] Transmitting ZK proof parameters signature: proof_z = 9A82F...E09B`);
                beamPath.classList.add('sending-beam');
            }, 2500);

            // Phase 5: Verifier computes checks validation checks
            setTimeout(() => {
                beamPath.classList.remove('sending-beam');
                appendZkpLog("verifier", `[Verifier Node] Proof packet received. Calculating validation check check formula: g^z == C * (h^c * y).`);
                
                // Emulate cryptographic evaluation checking curves pairings
                appendZkpLog("success", `[Verifier Math] Equation matches! Pairings verified mathematically without receiving cleartext passcode s.`);
                appendZkpLog("success", `[ZKP Engine] Validation succeeded. Prover node authorized.`);
                
                actorProver.querySelector('.actor-status').textContent = "Authed";
                actorVerifier.querySelector('.actor-status').textContent = "Verified";
                
                // Show badge
                verifBadgeText.textContent = "ZK-PROOF VERIFIED";
                verifBadgeText.className = "badge-body verified";
                verifBadge.style.display = 'block';

                window.addTimelineLog(`ZK Handshake succeeded. Identity verified mathematically using ${selectedCurve.toUpperCase()} curve curves.`);
                window.showStatusOverlay("ZK-Proof Authed", "User passcode verified using zero-knowledge snarks", 1500);
            }, 3600);
        });
    }

    const appendZkpLog = (type, text) => {
        if (!logBox) return;
        const line = document.createElement('div');
        line.className = `zk-log-line ${type}`;
        line.textContent = text;
        logBox.appendChild(line);
        logBox.scrollTop = logBox.scrollHeight;
    };

})();

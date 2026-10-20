// --- SENTINELOS Incident Response Automation ---

document.addEventListener('DOMContentLoaded', () => {
    const selectPlaybook = document.getElementById('inc-playbook-select');
    const btnExecute = document.getElementById('btn-execute-playbook');
    const stepsBox = document.getElementById('playbook-steps-box');
    const toggleIsolate = document.getElementById('safety-isolate');
    const toggleAlert = document.getElementById('safety-alert');

    if (!selectPlaybook || !btnExecute || !stepsBox) return;

    // Define detailed visual steps for each mitigation playbook campaign
    const playbooks = {
        ransomware: [
            { title: "Isolate Infected Subnet Range", desc: "Forcing hardware port isolation protocols on subgrid C-2." },
            { title: "Extract Volatile RAM Logs", desc: "Dumping registers and cache sectors to secure memory box." },
            { title: "Deploy Lattice Encryption Patches", desc: "Replacing compromised public key parameters with Kyber-1024." },
            { title: "Commit Audit Proofs to Ledger", desc: "Sealing forensic evidence blocks inside immutable blockchain." }
        ],
        ddos: [
            { title: "Analyze Core Network Ingress", desc: "Mapping volumetric packet flooding routes and tracking botnet origin IPs." },
            { title: "Reroute Bad Traffic to Decoy", desc: "Rewriting BGP rules to redirect hostile IP flows into deception grid." },
            { title: "Activate Modbus Deception Honeytrap", desc: "Simulating vulnerable SCADA controller interfaces on subnet E-4." },
            { title: "Verify Quantum Ledger Sync", desc: "Re-indexing secured node configurations and closing perimeter gates." }
        ],
        zeroday: [
            { title: "Isolate Rogue Core Nodes", desc: "Quarantining active API pathways to host subnode 14." },
            { title: "Generate Lattice-MLWE Kyber Keys", desc: "Synthesizing high-entropy key pairs resilient to Shor attack models." },
            { title: "Recalibrate AI Threat Predictors", desc: "Feeding zero-day heuristic metrics into correlation models." },
            { title: "Audit System Scorecard Clearance", desc: "Re-verifying Root Admin biometrics and indexing secure ledger blocks." }
        ]
    };

    // Render steps list inside the box
    const renderSteps = (playbookKey) => {
        const steps = playbooks[playbookKey];
        if (!steps) return;
        
        stepsBox.innerHTML = '';
        steps.forEach((step, idx) => {
            const stepDiv = document.createElement('div');
            stepDiv.className = "flow-step";
            stepDiv.id = `step-${idx}`;
            stepDiv.innerHTML = `
                <div class="step-badge">${idx + 1}</div>
                <div class="step-body">
                    <strong>${step.title}</strong>
                    <p class="status-text">Pending Trigger</p>
                </div>
            `;
            stepsBox.appendChild(stepDiv);
        });
    };

    // Initialize with default select selection
    renderSteps(selectPlaybook.value);

    // Swap steps dynamically upon select modification
    selectPlaybook.addEventListener('change', () => {
        renderSteps(selectPlaybook.value);
        window.addTimelineLog(`Selected Playbook Profile updated: ${selectPlaybook.options[selectPlaybook.selectedIndex].text}`);
    });

    // Execute flow graph sequentially
    btnExecute.addEventListener('click', () => {
        const selectedKey = selectPlaybook.value;
        const steps = playbooks[selectedKey];
        if (!steps) return;

        // Block UI controls while executing playbook
        btnExecute.disabled = true;
        selectPlaybook.disabled = true;
        if (toggleIsolate) toggleIsolate.disabled = true;
        if (toggleAlert) toggleAlert.disabled = true;

        window.addTimelineLog(`INCIDENT TRIGGER: Initiating automation playbook containment sequence: ${selectPlaybook.options[selectPlaybook.selectedIndex].text}`);
        window.showStatusOverlay("Executing Playbook", "Orchestrating containment workflow graph...", 1200);

        let currentStepIdx = 0;

        const executeStep = () => {
            if (currentStepIdx > 0) {
                // Mark previous step as completed
                const prevStep = document.getElementById(`step-${currentStepIdx - 1}`);
                if (prevStep) {
                    prevStep.classList.remove('active');
                    prevStep.classList.add('completed');
                    const statusText = prevStep.querySelector('.status-text');
                    if (statusText) statusText.textContent = "COMPLETED";
                }
            }

            if (currentStepIdx < steps.length) {
                // Focus and activate current step
                const currentStep = document.getElementById(`step-${currentStepIdx}`);
                if (currentStep) {
                    currentStep.classList.add('active');
                    const statusText = currentStep.querySelector('.status-text');
                    if (statusText) statusText.textContent = "EXECUTING: " + steps[currentStepIdx].desc;
                    
                    window.addTimelineLog(`[Playbook] Step ${currentStepIdx + 1}/${steps.length} running: ${steps[currentStepIdx].title}`);
                }

                currentStepIdx++;
                setTimeout(executeStep, 1500); // 1.5 seconds delay between steps
            } else {
                // Containment sequence finished!
                const lastStep = document.getElementById(`step-${steps.length - 1}`);
                if (lastStep) {
                    lastStep.classList.remove('active');
                    lastStep.classList.add('completed');
                    const statusText = lastStep.querySelector('.status-text');
                    if (statusText) statusText.textContent = "COMPLETED";
                }

                // Restore UI controls
                btnExecute.disabled = false;
                selectPlaybook.disabled = false;
                if (toggleIsolate) toggleIsolate.disabled = false;
                if (toggleAlert) toggleAlert.disabled = false;

                window.addTimelineLog(`PLAYBOOK SUCCESS: ${selectPlaybook.options[selectPlaybook.selectedIndex].text} fully containment-verified.`);
                
                // Alert verification success overlay
                window.showStatusOverlay("Threat Contained", "Mitigation flow completed successfully. Threat signatures neutralized.", 1800);

                // Decrement dashboard active threats count as we successfully neutralized one!
                if (window.updateActiveThreatsCount) {
                    window.updateActiveThreatsCount(-1);
                }
            }
        };

        // Trigger first step
        setTimeout(executeStep, 800);
    });
});

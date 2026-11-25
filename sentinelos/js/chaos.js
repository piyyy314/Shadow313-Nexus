// --- SentinelOS Red Team Chaos Engineering Simulator ---

document.addEventListener('DOMContentLoaded', () => {
    const gridContainer = document.getElementById('chaos-grid-container');
    const selectVector = document.getElementById('chaos-vector');
    const btnInject = document.getElementById('btn-chaos-inject');
    const healFill = document.getElementById('chaos-heal-fill');
    const healText = document.getElementById('chaos-heal-text');
    const logScreen = document.getElementById('chaos-log-screen');

    if (!gridContainer || !btnInject || !healFill || !healText || !logScreen) return;

    const totalNodesCount = 18;
    let nodeElements = [];
    let isSimulationRunning = false;

    // 1. Initialize 18-node topology grid
    window.initChaosView = () => {
        gridContainer.innerHTML = '';
        nodeElements = [];
        
        for (let i = 1; i <= totalNodesCount; i++) {
            const nodeVal = i < 10 ? `0${i}` : `${i}`;
            const node = document.createElement('div');
            node.className = "topo-node";
            node.textContent = nodeVal;
            node.title = `Sample Node-${nodeVal} (Demo State)`;
            
            // Allow interactive manual node infection toggles!
            node.addEventListener('click', () => {
                if (isSimulationRunning) return;
                toggleNodeManual(node, nodeVal);
            });

            gridContainer.appendChild(node);
            nodeElements.push(node);
        }
        
        // Reset logs
        logScreen.innerHTML = '<div class="log-line text-green">[DEMO] Sample topology initialized. No platform nodes are connected.</div>';
        updateHealthIndicator();
    };

    // Trigger grid initialization
    window.initChaosView();

    // Toggle node state manually
    const toggleNodeManual = (node, nodeVal) => {
        if (node.classList.contains('down')) {
            // Heal node manually
            node.className = "topo-node rebuilding";
            node.title = `Sample Node-${nodeVal} (Demo Animation...)`;
            writeLogLine(`[DEMO] Animating a sample rebuild for Node-${nodeVal}; no patch is deployed.`, 'text-orange');
            
            setTimeout(() => {
                node.className = "topo-node";
                node.title = `Host Node-${nodeVal} (Healthy)`;
                writeLogLine(`[DEMO] Sample Node-${nodeVal} animation reset; no host was restored.`, 'text-green');
                updateHealthIndicator();
            }, 1000);
        } else {
            // Infect node manually
            node.className = "topo-node down";
            node.title = `Sample Node-${nodeVal} (Demo Outage State)`;
            writeLogLine(`[DEMO] Sample outage state toggled for Node-${nodeVal}; no communications link changed.`, 'text-red');
            updateHealthIndicator();
            
            if (window.updateActiveThreatsCount) {
                window.updateActiveThreatsCount(1);
            }
        }
    };

    // Calculate and update health metrics
    const updateHealthIndicator = () => {
        const downedNodes = gridContainer.querySelectorAll('.topo-node.down').length;
        const rebuildingNodes = gridContainer.querySelectorAll('.topo-node.rebuilding').length;
        
        const healthFraction = (totalNodesCount - downedNodes - (rebuildingNodes * 0.5)) / totalNodesCount;
        const healthPercent = Math.max(0, Math.min(100, Math.round(healthFraction * 100)));
        
        healFill.style.width = `${healthPercent}%`;
        
        // Dynamic colors for heal bar classes
        if (healthPercent >= 90) {
            healFill.className = "heal-bar";
            healText.className = "heal-percent";
            healText.textContent = `DEMO: ${healthPercent}% SAMPLE STATE`;
        } else if (healthPercent >= 60) {
            healFill.className = "heal-bar warning";
            healText.className = "heal-percent warning";
            healText.textContent = `DEMO: ${healthPercent}% SAMPLE WARNING`;
        } else {
            healFill.className = "heal-bar critical";
            healText.className = "heal-percent critical";
            healText.textContent = `DEMO: ${healthPercent}% SAMPLE OUTAGE`;
        }
    };

    // Diagnostic logger helper
    const writeLogLine = (text, className = '') => {
        const line = document.createElement('div');
        line.className = `log-line ${className}`;
        line.textContent = `[${new Date().toLocaleTimeString('en-US', {hour12:false})}] ${text}`;
        logScreen.appendChild(line);
        logScreen.scrollTop = logScreen.scrollHeight;
    };

    // Ingress chaos events based on selected profile
    btnInject.addEventListener('click', () => {
        if (isSimulationRunning) return;
        isSimulationRunning = true;
        btnInject.disabled = true;
        selectVector.disabled = true;

        const vector = selectVector.value;
        let targets = [];

        // Define targets index mapping for different campaigns
        if (vector === 'outage') {
            targets = [2, 3, 6, 7, 8, 11]; // Nodes: 03, 04, 07, 08, 09, 12
            writeLogLine("DEMO: Animating a sample network-partition scenario.", "text-red");
        } else if (vector === 'hijack') {
            targets = [0, 4, 9, 13, 14]; // Nodes: 01, 05, 10, 14, 15
            writeLogLine("DEMO: Animating a sample telemetry-hijack scenario.", "text-red");
        } else if (vector === 'ransom') {
            targets = [1, 5, 7, 10, 15, 16]; // Nodes: 02, 06, 08, 11, 16, 17
            writeLogLine("DEMO: Animating a sample ransomware scenario; no database is accessed.", "text-red");
        }

        window.showStatusOverlay("Running Demo Scenario", "Updating sample node states in the browser only.", 1200);
        window.addTimelineLog(`CHAOS EVENT: Red Team simulated intrusion injected: ${selectVector.options[selectVector.selectedIndex].text}`);

        if (window.updateActiveThreatsCount) {
            window.updateActiveThreatsCount(1);
        }

        // 2. Disrupt target nodes simultaneously
        setTimeout(() => {
            targets.forEach(idx => {
                const node = nodeElements[idx];
                if (node) {
                    node.className = "topo-node down";
                    node.title = `Host Node-${idx+1} (CRITICAL OUTAGE)`;
                    writeLogLine(`[BREACH ALERT] Communication link lost on Node-${idx+1 < 10 ? '0'+(idx+1) : idx+1}!`, 'text-red');
                }
            });
            updateHealthIndicator();

            // 3. Initiate automatic AI self-healing cycle
            setTimeout(() => {
                writeLogLine("[DEMO] Displaying a scripted repair animation; no quarantine action occurred.", "text-orange");
                
                let repairStep = 0;
                const repairInterval = setInterval(() => {
                    if (repairStep < targets.length) {
                        const targetIdx = targets[repairStep];
                        const node = nodeElements[targetIdx];
                        const nodeNum = targetIdx + 1 < 10 ? '0' + (targetIdx + 1) : targetIdx + 1;

                        if (node) {
                            // Phase A: Rebuild
                            node.className = "topo-node rebuilding";
                            node.title = `Host Node-${nodeNum} (Rebuilding...)`;
                            writeLogLine(`[DEMO] Sample containment/key-rotation step shown for Node-${nodeNum}; no action occurred.`, 'text-orange');
                            updateHealthIndicator();

                            // Phase B: Restore (staggered slightly)
                            setTimeout(() => {
                                node.className = "topo-node";
                                node.title = `Host Node-${nodeNum} (Healthy)`;
                                writeLogLine(`[DEMO] Sample Node-${nodeNum} visual state reset; no host was restored or synced.`, 'text-green');
                                updateHealthIndicator();
                            }, 500);
                        }

                        repairStep++;
                    } else {
                        clearInterval(repairInterval);
                        
                        // Simulation completed!
                        setTimeout(() => {
                            isSimulationRunning = false;
                            btnInject.disabled = false;
                            selectVector.disabled = false;
                            
                            writeLogLine("[DEMO] Browser scenario complete; no infrastructure was repaired or synchronized.", "text-green");
                            updateHealthIndicator();

                            window.addTimelineLog("DEMO: Sample node animations finished; no network containment or repair was performed.");
                            window.showStatusOverlay("Demo Scenario Complete", "Sample node states reset in the browser; no infrastructure action occurred.", 1800);
                            
                            if (window.updateActiveThreatsCount) {
                                window.updateActiveThreatsCount(-1);
                            }
                        }, 800);
                    }
                }, 900); // Process each repair step sequentially

            }, 1500);

        }, 1000);
    });
});

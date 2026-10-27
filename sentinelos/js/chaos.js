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
            node.title = `Host Node-${nodeVal} (Healthy)`;
            
            // Allow interactive manual node infection toggles!
            node.addEventListener('click', () => {
                if (isSimulationRunning) return;
                toggleNodeManual(node, nodeVal);
            });

            gridContainer.appendChild(node);
            nodeElements.push(node);
        }
        
        // Reset logs
        logScreen.innerHTML = '<div class="log-line text-green">[Engine] All platform subnodes running healthy. Waiting for incident payloads...</div>';
        updateHealthIndicator();
    };

    // Trigger grid initialization
    window.initChaosView();

    // Toggle node state manually
    const toggleNodeManual = (node, nodeVal) => {
        if (node.classList.contains('down')) {
            // Heal node manually
            node.className = "topo-node rebuilding";
            node.title = `Host Node-${nodeVal} (Rebuilding...)`;
            writeLogLine(`[Manual] Rebuilding Node-${nodeVal}... deploying encryption patch.`, 'text-orange');
            
            setTimeout(() => {
                node.className = "topo-node";
                node.title = `Host Node-${nodeVal} (Healthy)`;
                writeLogLine(`[Manual] Node-${nodeVal} fully restored to secure cluster.`, 'text-green');
                updateHealthIndicator();
            }, 1000);
        } else {
            // Infect node manually
            node.className = "topo-node down";
            node.title = `Host Node-${nodeVal} (CRITICAL OUTAGE)`;
            writeLogLine(`[Manual Alert] Critical communications disruption forced on Node-${nodeVal}!`, 'text-red');
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
            healText.textContent = `${healthPercent}% HEALTHY`;
        } else if (healthPercent >= 60) {
            healFill.className = "heal-bar warning";
            healText.className = "heal-percent warning";
            healText.textContent = `${healthPercent}% STRESSED`;
        } else {
            healFill.className = "heal-bar critical";
            healText.className = "heal-percent critical";
            healText.textContent = `${healthPercent}% CRITICAL OUTAGE`;
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
            writeLogLine("RED-TEAM: Injecting Cascade Network Partition Outage payload...", "text-red");
        } else if (vector === 'hijack') {
            targets = [0, 4, 9, 13, 14]; // Nodes: 01, 05, 10, 14, 15
            writeLogLine("RED-TEAM: Injecting Hostile AI Node Telemetry Hijack script...", "text-red");
        } else if (vector === 'ransom') {
            targets = [1, 5, 7, 10, 15, 16]; // Nodes: 02, 06, 08, 11, 16, 17
            writeLogLine("RED-TEAM: Executing Ransomware Database Crypt simulator...", "text-red");
        }

        window.showStatusOverlay("Injecting Chaos", "Executing host partitions telemetry breach...", 1200);
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
                writeLogLine("[ORCHESTRATOR] SentinelOS AI self-healing system triggered. Quarantining infected sectors...", "text-orange");
                
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
                            writeLogLine(`[HEAL] Securing sandbox containment & rotating keys on Node-${nodeNum}.`, 'text-orange');
                            updateHealthIndicator();

                            // Phase B: Restore (staggered slightly)
                            setTimeout(() => {
                                node.className = "topo-node";
                                node.title = `Host Node-${nodeNum} (Healthy)`;
                                writeLogLine(`[HEAL] Node-${nodeNum} fully restored and synced to active cluster.`, 'text-green');
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
                            
                            writeLogLine("[Engine] Auto-healing routine completed. Subnet infrastructure fully synchronized.", "text-green");
                            updateHealthIndicator();

                            window.addTimelineLog("CHAOS MITIGATION: AI Self-Healing finished. All partitioned subnodes repaired.");
                            window.showStatusOverlay("Self-Healing Completed", "All network nodes successfully recovered to 100% health.", 1800);
                            
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

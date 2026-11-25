// --- SENTINELOS Honeypot Deception Network ---

document.addEventListener('DOMContentLoaded', () => {
    const decoySelect = document.getElementById('dec-type');
    const baitArea = document.getElementById('txt-dec-bait');
    const btnDeploy = document.getElementById('btn-deploy-decoy');
    const activeCounter = document.getElementById('active-honeypots-count');
    const subnetGrid = document.getElementById('subnet-decoy-grid');
    const logBox = document.getElementById('dec-log-box');

    if (!decoySelect || !baitArea || !btnDeploy || !activeCounter || !subnetGrid || !logBox) return;

    const totalGridSlots = 24;
    let sampleDecoys = [
        { index: 2, label: "DEC-01", type: "SCADA", bait: "Modbus PLC v3.1" },
        { index: 9, label: "DEC-02", type: "SQL", bait: "MySQL Fin Records" },
        { index: 17, label: "DEC-03", type: "SSH", bait: "Admin Terminal" }
    ];

    // Standard preset bait templates for the text area configuration
    const baits = {
        scada: JSON.stringify({ "controller": "Modbus_PLC_v3", "ports": [502], "canary_token": "TOK-PLC-881" }, null, 2),
        mysql: JSON.stringify({ "decoy_db": "cust_records_fin", "bait_rows": 1250, "canary_token": "TOK-SQL-558" }, null, 2),
        ssh: JSON.stringify({ "host": "sentinel-core-ssh", "banner": "Ubuntu 22.04 LTS", "canary_token": "TOK-SSH-901" }, null, 2)
    };

    // Update bait text area dynamically when selection changes
    decoySelect.addEventListener('change', () => {
        baitArea.value = baits[decoySelect.value] || "";
    });

    // 1. Initialize Subgrid View
    window.initDeceptionView = () => {
        subnetGrid.innerHTML = '';
        activeCounter.textContent = sampleDecoys.length;

        for (let i = 0; i < totalGridSlots; i++) {
            const slot = document.createElement('div');
            slot.className = "subnet-block";
            
            // Check if there is a decoy deployed on this slot index
            const decoy = sampleDecoys.find(d => d.index === i);
            if (decoy) {
                slot.className = "subnet-block decoy";
                slot.textContent = `${decoy.label}`;
                slot.title = `Sample Honeypot (${decoy.type}) - ${decoy.bait}`;
                
                // Allow tripping preloaded honeypots manually!
                slot.addEventListener('click', () => {
                    simulateHoneypotEvent(slot, decoy);
                });
            } else {
                const gridLetter = String.fromCharCode(65 + Math.floor(i / 8)); // A, B, C
                const gridNumber = (i % 8) + 1; // 1-8
                slot.textContent = `${gridLetter}-${gridNumber}`;
                slot.title = `Unused Subnet Block (${gridLetter}-${gridNumber})`;
            }

            subnetGrid.appendChild(slot);
        }
    };

    // Trigger grid render
    window.initDeceptionView();

    // Logger diagnostic helper
    const writeLogLine = (text, type = 'info') => {
        const line = document.createElement('div');
        line.className = "log-line";
        
        let colorClass = "";
        let prefix = "[INFO]";
        if (type === 'warn') { colorClass = "text-orange"; prefix = "[WARN]"; }
        if (type === 'alert') { colorClass = "text-red"; prefix = "[ALERT]"; }
        if (type === 'success') { colorClass = "text-green"; prefix = "[DEMO]"; }
        
        line.className = `log-line ${colorClass}`;
        line.textContent = `[${new Date().toLocaleTimeString('en-US', {hour12:false})}] ${prefix} ${text}`;
        
        logBox.appendChild(line);
        logBox.scrollTop = logBox.scrollHeight;
    };

    // 2. Deploy Honeypot Decoy
    btnDeploy.addEventListener('click', () => {
        const type = decoySelect.value;
        const baitContent = baitArea.value.trim();

        // Validate JSON bait structure
        let parsedBait = {};
        try {
            parsedBait = JSON.parse(baitContent);
        } catch (e) {
            writeLogLine("Bait Configuration is not valid JSON. Utilizing fallback parameters.", "warn");
            parsedBait = { "canary_token": "TOK-GENERIC" };
        }

        // Find next empty index in grid
        let emptyIndex = -1;
        for (let i = 0; i < totalGridSlots; i++) {
            if (!sampleDecoys.some(d => d.index === i)) {
                emptyIndex = i;
                break;
            }
        }

        if (emptyIndex === -1) {
            window.showStatusOverlay("Demo Grid Full", "No sample slots remain in this browser demonstration.", 1500);
            return;
        }

        // Add a browser-only sample decoy configuration
        const nextIdNum = sampleDecoys.length + 1;
        const newDecoy = {
            index: emptyIndex,
            label: nextIdNum < 10 ? `DEC-0${nextIdNum}` : `DEC-${nextIdNum}`,
            type: type.toUpperCase(),
            bait: parsedBait.decoy_db || parsedBait.controller || parsedBait.host || "Bait Pack"
        };

        sampleDecoys.push(newDecoy);
        window.showStatusOverlay("Adding Sample Decoy", `Updating the illustrative ${newDecoy.type} scenario...`, 1200);
        window.addTimelineLog(`DEMO: Sample decoy ${newDecoy.label} (${newDecoy.type}) added in the browser; no honeypot or listening port was deployed.`);

        setTimeout(() => {
            window.initDeceptionView();
            writeLogLine(`DEMO: Sample ${newDecoy.type} decoy (${newDecoy.label}) displayed. No bait service was started and no port was opened.`, 'info');

            // 3. Stagger simulated intrusion on the newly deployed trap (after 3 seconds)
            setTimeout(() => {
                const blocks = subnetGrid.children;
                const newSlotNode = blocks[newDecoy.index];
                if (newSlotNode) {
                    simulateHoneypotEvent(newSlotNode, newDecoy);
                }
            }, 3000);

        }, 1200);
    });

    // 4. Intrusion Entrapment Simulation Sequence
    const simulateHoneypotEvent = (slotNode, decoy) => {
        if (slotNode.classList.contains('tripped')) return; // Already tripped
        
        slotNode.className = "subnet-block decoy tripped";
        writeLogLine(`DEMO: Synthetic intrusion scenario triggered for sample ${decoy.label} (${decoy.type}). No attacker was observed.`, 'warn');
        window.addTimelineLog(`DEMO: Synthetic event sequence started for sample decoy ${decoy.label}; no network traffic was received.`);
        
        if (window.updateActiveThreatsCount) {
            window.updateActiveThreatsCount(1);
        }

        // Trigger step-by-step scrolling diagnostic hacker shell telemetry logs
        const traceLogs = [
            `DEMO: Sample source address 185.220.101.55 displayed; no inbound handshake occurred.`,
            `DEMO: Illustrative TCP/UDP discovery step; no probe was sent.`,
            `DEMO: Sample decoy banner displayed: '${decoy.bait}'.`,
            `DEMO: Sample password-guessing step displayed; no accounts were contacted.`,
            `DEMO: Scripted guest-login step; no authentication or shell was created.`,
            `DEMO: Sample SQL query displayed; no database connection was made.`,
            `DEMO: Sample canary event displayed; no token was observed or recorded.`,
            `DEMO: Sample containment step displayed; no host was isolated and no ledger was written.`
        ];

        let logIdx = 0;
        const logTimer = setInterval(() => {
            if (logIdx < traceLogs.length) {
                writeLogLine(traceLogs[logIdx], logIdx === 0 || logIdx === 6 ? 'alert' : 'warn');
                logIdx++;
            } else {
                clearInterval(logTimer);
                writeLogLine(`DEMO: Browser scenario complete. No intrusion was detected, contained, or recorded.`, 'info');
                window.addTimelineLog(`DEMO: Sample sequence for ${decoy.label} ended; no forensic evidence was collected.`);

                if (window.updateActiveThreatsCount) {
                    window.updateActiveThreatsCount(-1);
                }
            }
        }, 1200);
    };
});

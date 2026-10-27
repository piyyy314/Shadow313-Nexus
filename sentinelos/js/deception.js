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
    let deployedDecoys = [
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
        activeCounter.textContent = deployedDecoys.length;

        for (let i = 0; i < totalGridSlots; i++) {
            const slot = document.createElement('div');
            slot.className = "subnet-block";
            
            // Check if there is a decoy deployed on this slot index
            const decoy = deployedDecoys.find(d => d.index === i);
            if (decoy) {
                slot.className = "subnet-block decoy";
                slot.textContent = `${decoy.label}`;
                slot.title = `Active Honeypot (${decoy.type}) - ${decoy.bait}`;
                
                // Allow tripping preloaded honeypots manually!
                slot.addEventListener('click', () => {
                    tripHoneypotIntrusion(slot, decoy);
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
        if (type === 'success') { colorClass = "text-green"; prefix = "[SUCCESS]"; }
        
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
            if (!deployedDecoys.some(d => d.index === i)) {
                emptyIndex = i;
                break;
            }
        }

        if (emptyIndex === -1) {
            window.showStatusOverlay("Grid Overloaded", "No empty network slots available to deploy honey decoy.", 1500);
            return;
        }

        // Deploy new decoy node configuration
        const nextIdNum = deployedDecoys.length + 1;
        const newDecoy = {
            index: emptyIndex,
            label: nextIdNum < 10 ? `DEC-0${nextIdNum}` : `DEC-${nextIdNum}`,
            type: type.toUpperCase(),
            bait: parsedBait.decoy_db || parsedBait.controller || parsedBait.host || "Bait Pack"
        };

        deployedDecoys.push(newDecoy);
        window.showStatusOverlay("Deploying Decoy", `Configuring dynamic ${newDecoy.type} honeypot...`, 1200);
        window.addTimelineLog(`DECEPTION DEPLOYED: Honeypot Decoy ${newDecoy.label} (${newDecoy.type}) online on subgrid block.`);

        setTimeout(() => {
            window.initDeceptionView();
            writeLogLine(`Dynamic ${newDecoy.type} Honeypot Decoy (${newDecoy.label}) deployed successfully. Bait registered. Listening on active ports.`, 'success');

            // 3. Stagger simulated intrusion on the newly deployed trap (after 3 seconds)
            setTimeout(() => {
                const blocks = subnetGrid.children;
                const newSlotNode = blocks[newDecoy.index];
                if (newSlotNode) {
                    tripHoneypotIntrusion(newSlotNode, newDecoy);
                }
            }, 3000);

        }, 1200);
    });

    // 4. Intrusion Entrapment Simulation Sequence
    const tripHoneypotIntrusion = (slotNode, decoy) => {
        if (slotNode.classList.contains('tripped')) return; // Already tripped
        
        slotNode.className = "subnet-block decoy tripped";
        writeLogLine(`ATTACK DETECTED on ${decoy.label} (${decoy.type})! Perimeter alarm tripped!`, 'alert');
        window.addTimelineLog(`INTRUSION WARNING: Attacker locked onto Deception Honeypot ${decoy.label}!`);
        
        if (window.updateActiveThreatsCount) {
            window.updateActiveThreatsCount(1);
        }

        // Trigger step-by-step scrolling diagnostic hacker shell telemetry logs
        const traceLogs = [
            `Inbound network handshake established from Tor Gateway exit [185.220.101.55]`,
            `Hostile agent initiated aggressive TCP/UDP port mapping probe.`,
            `Accessing decoy interface banner: '${decoy.bait}'...`,
            `Hacker attempted brute-force password guessing dictionary attack (24 accounts scanned)...`,
            `Credential authorization succeeded for guest account. Spawning honeypot shell.`,
            `Attacker executed diagnostic query: 'SELECT * FROM information_schema.tables;'`,
            `Bait data extracted. Canary Token signature recorded!`,
            `Attacker isolated! Footprint hashes logged to blockchain ledger block.`
        ];

        let logIdx = 0;
        const logTimer = setInterval(() => {
            if (logIdx < traceLogs.length) {
                writeLogLine(traceLogs[logIdx], logIdx === 0 || logIdx === 6 ? 'alert' : 'warn');
                logIdx++;
            } else {
                clearInterval(logTimer);
                writeLogLine(`Intrusion successfully contained. Attacker routing trapped in endless loop. Sandbox metrics synced.`, 'success');
                window.addTimelineLog(`DECEPTION SUCCESS: Intrusion footprint on Honeypot ${decoy.label} captured and neutralized.`);

                if (window.updateActiveThreatsCount) {
                    window.updateActiveThreatsCount(-1);
                }
            }
        }, 1200);
    };
});

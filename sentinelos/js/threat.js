// --- SENTINELOS Predictive Threat Intelligence Engine ---

(() => {
    let canvas, ctx;
    let animId;
    let attackSources = [];
    let mapGridPoints = [];
    let homeNode = { x: 0, y: 0 };
    
    // Initialize threat visualizer view
    window.initThreatView = () => {
        canvas = document.getElementById('threat-map-canvas');
        if (canvas) {
            ctx = canvas.getContext('2d');
            resizeMapCanvas();
            initMockMapLandmasses();
            
            homeNode = {
                x: canvas.width * 0.3, // Roughly US East Coast
                y: canvas.height * 0.4
            };

            // Spawn initial attack targets
            spawnAttackNode();
            
            if (animId) cancelAnimationFrame(animId);
            animateThreatMap();
        }
    };

    const resizeMapCanvas = () => {
        if (!canvas) return;
        const rect = canvas.parentElement.getBoundingClientRect();
        canvas.width = rect.width;
        canvas.height = rect.height || 300;
    };

    window.addEventListener('resize', resizeMapCanvas);

    // Draw coordinate dots of map grid nodes
    const initMockMapLandmasses = () => {
        mapGridPoints = [];
        const cols = 26;
        const rows = 12;
        const spacingX = canvas.width / cols;
        const spacingY = canvas.height / rows;

        // Custom shape arrays approximating landmass grids
        const landmap = [
            [0,0,1,1,1,1,0,0,0,0,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0],
            [0,1,1,1,1,1,1,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0],
            [1,1,1,1,1,1,1,1,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0],
            [0,1,1,1,1,1,1,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,0],
            [0,0,1,1,1,1,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,0,0,0],
            [0,0,1,1,1,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,0,0,0,0],
            [0,0,0,1,1,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,0,0,0,0,0,0],
            [0,0,0,1,0,0,0,0,0,0,0,0,0,0,1,1,1,1,0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,0,0,0,0,0,0,0],
            [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0]
        ];

        for (let r = 0; r < rows; r++) {
            for (let c = 0; c < cols; c++) {
                if (landmap[r] && landmap[r][c] === 1) {
                    mapGridPoints.push({
                        x: c * spacingX + spacingX / 2 + Math.random() * 2,
                        y: r * spacingY + spacingY / 2 + Math.random() * 2,
                        pulse: Math.random() * Math.PI
                    });
                }
            }
        }
    };

    const spawnAttackNode = () => {
        if (!canvas) return;
        // Spawn attack point at European, Asian, or South American coordinates
        const locationType = Math.random();
        let srcX = 0, srcY = 0;

        if (locationType < 0.4) {
            // Europe
            srcX = canvas.width * 0.55 + Math.random() * 60;
            srcY = canvas.height * 0.28 + Math.random() * 40;
        } else if (locationType < 0.8) {
            // Asia
            srcX = canvas.width * 0.75 + Math.random() * 80;
            srcY = canvas.height * 0.35 + Math.random() * 50;
        } else {
            // South America
            srcX = canvas.width * 0.35 + Math.random() * 40;
            srcY = canvas.height * 0.68 + Math.random() * 50;
        }

        attackSources.push({
            x: srcX,
            y: srcY,
            progress: 0,
            speed: 0.015 + Math.random() * 0.01,
            pulse: 0,
            active: true
        });

        // Maximum 5 visual attack coordinates to maintain clean render
        if (attackSources.length > 5) {
            attackSources.shift();
        }
    };

    // Main map rendering loops
    const animateThreatMap = () => {
        if (!canvas || !ctx) return;
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        // 1. Draw static grid coordinates map outline
        ctx.fillStyle = 'rgba(230, 241, 255, 0.03)';
        mapGridPoints.forEach(p => {
            p.pulse += 0.03;
            const deltaSize = Math.sin(p.pulse) * 0.5;
            ctx.beginPath();
            ctx.arc(p.x, p.y, 1.2 + deltaSize, 0, Math.PI * 2);
            ctx.fill();
        });

        // 2. Draw administrative home base node
        ctx.strokeStyle = 'rgba(72, 219, 251, 0.4)';
        ctx.lineWidth = 1.5;
        ctx.fillStyle = 'rgba(72, 219, 251, 0.15)';
        ctx.beginPath();
        ctx.arc(homeNode.x, homeNode.y, 6, 0, Math.PI * 2);
        ctx.stroke();
        ctx.fill();

        ctx.strokeStyle = 'var(--accent)';
        ctx.beginPath();
        ctx.arc(homeNode.x, homeNode.y, 12, 0, Math.PI * 2);
        ctx.stroke();

        // 3. Draw cyber attack vectors arcs and points
        attackSources.forEach((a, idx) => {
            if (!a.active) return;

            // Attack source node pulses
            a.pulse += 0.06;
            ctx.fillStyle = 'rgba(255, 107, 107, 0.6)';
            ctx.beginPath();
            ctx.arc(a.x, a.y, 4 + Math.sin(a.pulse) * 2, 0, Math.PI * 2);
            ctx.fill();

            // Trace parabolic Bezier arc to Home Node
            ctx.strokeStyle = 'rgba(255, 107, 107, 0.25)';
            ctx.lineWidth = 1;
            
            const midX = (a.x + homeNode.x) / 2;
            const midY = (a.y + homeNode.y) / 2 - 50; // Elevate center point to make arc curve upwards
            
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.quadraticCurveTo(midX, midY, homeNode.x, homeNode.y);
            ctx.stroke();

            // Draw traveling packet particle along arc path
            a.progress += a.speed;
            if (a.progress > 1.0) {
                // Packet reached target: register attack wave block
                a.active = false;
                triggerHoneypotTrapLog();
            } else {
                // Compute current position along bezier arc
                const t = a.progress;
                const px = (1 - t) * (1 - t) * a.x + 2 * (1 - t) * t * midX + t * t * homeNode.x;
                const py = (1 - t) * (1 - t) * a.y + 2 * (1 - t) * t * midY + t * t * homeNode.y;

                ctx.fillStyle = 'var(--danger)';
                ctx.beginPath();
                ctx.arc(px, py, 3.5, 0, Math.PI * 2);
                ctx.fill();
            }
        });

        // Randomly spawn new attacks
        if (Math.random() < 0.005) {
            spawnAttackNode();
        }

        animId = requestAnimationFrame(animateThreatMap);
    };

    // Hover coordinates tracking
    const mapCoords = document.getElementById('map-coords');
    if (canvas) {
        canvas.addEventListener('mousemove', (e) => {
            const rect = canvas.getBoundingClientRect();
            const mouseX = e.clientX - rect.left;
            const mouseY = e.clientY - rect.top;
            
            // Map coordinates to simulated lat/lon
            const lat = ((canvas.height / 2 - mouseY) * 0.45).toFixed(4);
            const lon = ((mouseX - canvas.width / 2) * 0.55).toFixed(4);
            
            if (mapCoords) {
                mapCoords.textContent = `RECEPTOR GRID: [Lat: ${lat}, Lon: ${lon}]`;
            }
        });
    }

    // Trigger alert loops when packet strikes target (Honeypot triggers)
    const triggerHoneypotTrapLog = () => {
        // Increment dashboard active threat counter
        window.updateActiveThreatsCount(1);
        
        const vectors = ["Port 22 Bruteforce Scan", "SQL injection vector", "API Authorization Overload Attempt", "Modbus payload injection"];
        const ips = ["185.190.140.23", "45.110.12.9", "103.99.204.14", "94.200.41.88"];
        
        const randVector = vectors[Math.floor(Math.random() * vectors.length)];
        const randIp = ips[Math.floor(Math.random() * ips.length)];
        
        // Add notification alert
        addPredictiveAlert("HIGH", `Hostile Intrusion: ${randVector}`, `Decoy asset trapped intrusion vector from ${randIp}. Mitigation automated.`);
        
        // Automatically mitigate after 3.5 seconds
        setTimeout(() => {
            window.updateActiveThreatsCount(-1);
            addPredictiveAlert("LOW", `Intrusion Mitigated`, `Threat vector isolated. IP ${randIp} blocked on all active subnets.`);
        }, 4000);
    };

    // Add alert card helper
    const addPredictiveAlert = (level, title, text) => {
        const scroller = document.getElementById('threat-intel-notifications');
        if (scroller) {
            const card = document.createElement('div');
            card.className = `threat-notif ${level.toLowerCase()}`;
            
            card.innerHTML = `
                <div class="notif-badge">AI ALERT</div>
                <div class="notif-body">
                    <strong>${title} [${level}]</strong>
                    <p>${text}</p>
                </div>
            `;
            scroller.insertBefore(card, scroller.firstChild);
            
            // Limit alert scrolling log counts
            if (scroller.children.length > 5) {
                scroller.removeChild(scroller.lastChild);
            }
        }
    };

    // Force Simulated Breach Button
    const btnSimAlert = document.getElementById('btn-sim-alert');
    if (btnSimAlert) {
        btnSimAlert.addEventListener('click', () => {
            // Spawn multiple attack coordinates
            for (let i = 0; i < 3; i++) {
                spawnAttackNode();
            }
            
            addPredictiveAlert("HIGH", "AI Prediction Breach Wave [Confidence: 99.4%]", "Simulated large-scale Red Team penetration campaign injected. Automated playbooks armed.");
            window.showStatusOverlay("Hostile Infiltration", "Warning: High volume intrusion vectors detected. Triggering Playbook...", 1500);
        });
    }

    // Recalibrate Receivers
    const btnRecalibrate = document.getElementById('btn-recalibrate-threats');
    if (btnRecalibrate) {
        btnRecalibrate.addEventListener('click', () => {
            initMockMapLandmasses();
            window.showStatusOverlay("Recalibrating...", "Tuning neural map geolocated threat receivers...", 1000);
            window.addTimelineLog("Threat map reception frequencies recalibrated.");
        });
    }

})();

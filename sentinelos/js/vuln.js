// --- SENTINELOS Automated Vulnerability Assessment Engine ---

(() => {
    const btnScan = document.getElementById('btn-vuln-scan');
    const targetInput = document.getElementById('txt-vuln-target');
    const profileSelect = document.getElementById('vuln-profile');
    
    const progressBox = document.getElementById('scan-progress-box');
    const progressText = document.getElementById('vuln-progress-text');
    const progressRing = document.getElementById('vuln-progress-ring');
    const phaseText = document.getElementById('vuln-phase-text');
    
    const scorecardEmpty = document.getElementById('vuln-scorecard-empty');
    const scorecardReport = document.getElementById('vuln-scorecard-report');

    if (btnScan) {
        btnScan.addEventListener('click', () => {
            const targetHost = targetInput.value.trim();
            const selectedProfile = profileSelect.value;

            if (!targetHost) {
                alert("Please enter a target host IP or Domain.");
                return;
            }

            // Reset and show progress ring loader
            progressBox.style.display = 'block';
            scorecardReport.style.display = 'none';
            scorecardEmpty.style.display = 'flex';
            
            let percent = 0;
            // Total stroke circum of ring is 251 (r=40)
            const ringCircum = 251;
            progressRing.style.strokeDashoffset = ringCircum;

            const scanPhases = [
                "Probing active host ports...",
                "Fuzzing HTTP server banners...",
                "Correlating vulnerabilities CVE mappings...",
                "Analyzing SSL/TLS cipher suites...",
                "Compiling audit scorecard report..."
            ];

            const sweepInterval = setInterval(() => {
                percent += 2;
                if (percent > 100) percent = 100;
                
                // Update text percent
                progressText.textContent = `${percent}%`;
                
                // Update SVG ring offset
                const offset = ringCircum - (percent / 100) * ringCircum;
                progressRing.style.strokeDashoffset = offset;

                // Update diagnostic phase text context
                const phaseIdx = Math.min(Math.floor((percent / 100) * scanPhases.length), scanPhases.length - 1);
                phaseText.textContent = scanPhases[phaseIdx];

                if (percent >= 100) {
                    clearInterval(sweepInterval);
                    progressBox.style.display = 'none';
                    
                    // Render scorecard report
                    compileAuditReport(targetHost, selectedProfile);
                }
            }, 50);
        });
    }

    const compileAuditReport = (host, profile) => {
        scorecardEmpty.style.display = 'none';
        scorecardReport.style.display = 'block';

        // Bind values dynamically
        document.getElementById('scorecard-summary-ip').textContent = `Host Node: ${host}`;
        document.getElementById('scorecard-timestamp').textContent = new Date().toLocaleString();

        const gradeEl = document.getElementById('vuln-grade');
        const countHigh = document.getElementById('vuln-count-high');
        const countMed = document.getElementById('vuln-count-med');
        const countLow = document.getElementById('vuln-count-low');
        const detailList = document.getElementById('vuln-detail-list');

        detailList.innerHTML = "";

        if (profile === 'quick') {
            gradeEl.textContent = "A";
            gradeEl.style.color = "var(--success)";
            gradeEl.style.borderColor = "var(--success)";
            gradeEl.style.boxShadow = "0 0 15px rgba(29, 209, 161, 0.2)";

            countHigh.textContent = "0";
            countMed.textContent = "0";
            countLow.textContent = "2";

            detailList.innerHTML = `
                <li class="low"><strong>Low Risk</strong> - Open HTTP server banner reveals minor version leaks (Apache 2.4).</li>
                <li class="low"><strong>Low Risk</strong> - SSL/TLS support includes deprecated TLS 1.1 handshakes.</li>
            `;
        } else if (profile === 'deep') {
            gradeEl.textContent = "B-";
            gradeEl.style.color = "var(--warning)";
            gradeEl.style.borderColor = "var(--warning)";
            gradeEl.style.boxShadow = "0 0 15px rgba(254, 202, 87, 0.2)";

            countHigh.textContent = "0";
            countMed.textContent = "2";
            countLow.textContent = "3";

            detailList.innerHTML = `
                <li class="medium"><strong>Medium Risk</strong> - Missing secure HTTP headers: X-Frame-Options & CSP limits framing clickjacking.</li>
                <li class="medium"><strong>Medium Risk</strong> - SSH daemon supports outdated MAC authentication algorithms.</li>
                <li class="low"><strong>Low Risk</strong> - Local DNS records mapping does not implement DNSSEC signatures.</li>
                <li class="low"><strong>Low Risk</strong> - Open NTP service reveals UDP port clock offsets.</li>
            `;
        } else {
            // Aggressive Deception scanning
            gradeEl.textContent = "D";
            gradeEl.style.color = "var(--danger)";
            gradeEl.style.borderColor = "var(--danger)";
            gradeEl.style.boxShadow = "0 0 15px rgba(255, 107, 107, 0.2)";

            countHigh.textContent = "2";
            countMed.textContent = "3";
            countLow.textContent = "1";

            detailList.innerHTML = `
                <li class="high"><strong>High Risk</strong> - SQL Injection Vulnerability mapped inside login receptor input parameters.</li>
                <li class="high"><strong>High Risk</strong> - SCADA port 502/modbus runs without authorization controls.</li>
                <li class="medium"><strong>Medium Risk</strong> - Open SSH server version exposes known memory overflow CVE-2023.</li>
                <li class="low"><strong>Low Risk</strong> - System root keys generate using low-entropy seed hashes.</li>
            `;
        }

        window.addTimelineLog(`Automated vulnerability audit completed for target ${host}. Grade: ${gradeEl.textContent}`);
        window.showStatusOverlay("Audit Scorecard", `Vulnerability assessment completed for ${host}`, 1200);
    };

})();

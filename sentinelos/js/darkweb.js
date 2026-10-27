// --- SENTINELOS Dark Web Monitoring & Breach Scanner ---

const escapeHtml = (str) => {
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
};

document.addEventListener('DOMContentLoaded', () => {
    const btnSearch = document.getElementById('btn-dw-search');
    const txtSearch = document.getElementById('txt-dw-search');
    const resultsList = document.getElementById('dw-results-list');

    if (!btnSearch || !resultsList) return;

    // Standard leak databank templates
    const generateBreachData = (query) => {
        const domain = escapeHtml(query.trim().toLowerCase() || "sentinelos.com");
        return [
            {
                source: "ALPHA-BAY-REBORN.ONION",
                date: "2026-05-18",
                desc: `Compromised administrator credentials matching core domain.`,
                detail: `<strong>Database:</strong> customer_vault_prod<br>
                         <strong>Email:</strong> admin@${domain}<br>
                         <strong>Decrypted Password:</strong> <span class="dw-masked" title="Hover to decrypt password">qT9$mK#8xP_sentinel</span>`
            },
            {
                source: "OMEGA-LEAKS-FORUM.ONION",
                date: "2026-05-10",
                desc: `SQL Database dump contains configurations matching internal subnets.`,
                detail: `<strong>Leaked Tables:</strong> system_auth_nodes, routing_rules_decoy<br>
                         <strong>Target IP Range:</strong> 192.168.100.0/24<br>
                         <strong>Decoded Bait:</strong> <span class="dw-masked" title="Hover to decrypt metadata">DB_SALT_ENTROPY=0x88f9a2cd...</span>`
            },
            {
                source: "CYBER-CARTEL-MARKET.ONION",
                date: "2026-05-02",
                desc: `Exploit threat listing targeting SentinelOS node vulnerabilities.`,
                detail: `<strong>Thread ID:</strong> #55982 - SentinelOS Remote Buffer Overflow exploit<br>
                         <strong>Listing Price:</strong> 0.48 BTC<br>
                         <strong>Exploit Target:</strong> <span class="dw-masked" title="Hover to decrypt vulnerability code">CVE-2026-9041 (SCADA Port 502 Bypass)</span>`
            }
        ];
    };

    btnSearch.addEventListener('click', () => {
        const query = txtSearch.value.trim();
        if (!query) {
            window.showStatusOverlay("Search Failed", "Please enter a valid query string...", 1200);
            return;
        }

        // 1. Initial State: Clear output and trigger status overlay
        resultsList.innerHTML = '';
        window.showStatusOverlay("Scanning Darknet", "Connecting to decentralized Tor Gateways...", 1200);
        window.addTimelineLog(`Initiating decentralized Dark Web breach search for: ${query}`);

        // 2. Render scrolling decryption status loading indicator
        const scanLoadingCard = document.createElement('div');
        scanLoadingCard.style.padding = '15px';
        scanLoadingCard.style.fontFamily = "'Fira Code', monospace";
        scanLoadingCard.style.fontSize = '12px';
        scanLoadingCard.style.color = 'var(--accent)';
        scanLoadingCard.innerHTML = `
            <div style="display:flex; align-items:center; gap:10px; margin-bottom:8px;">
                <div class="status-dot orange pulsing"></div>
                <span id="dw-status-phase">Resolving Onion exit nodes...</span>
            </div>
            <div id="dw-decryption-ticker" style="color:var(--text-muted); min-height:60px; line-height:1.4;"></div>
        `;
        resultsList.appendChild(scanLoadingCard);

        const statusPhase = document.getElementById('dw-status-phase');
        const decryptTicker = document.getElementById('dw-decryption-ticker');

        const scanPhrases = [
            "Querying Tor Hidden Service directory...",
            "Decrypting Onion-routing payload layers...",
            "Searching Paste repositories & leaked logs index...",
            "Correlating SQL database hashes with threat repositories...",
            "Compiling breach diagnostics..."
        ];

        let phraseIdx = 0;
        const phraseInterval = setInterval(() => {
            if (phraseIdx < scanPhrases.length) {
                statusPhase.textContent = scanPhrases[phraseIdx];
                phraseIdx++;
            }
        }, 400);

        // Rapid random hexadecimal scrambler stream
        const tickerInterval = setInterval(() => {
            let scrambleText = "";
            for (let i = 0; i < 3; i++) {
                const hexLine = Array.from({length: 32}, () => Math.floor(Math.random()*16).toString(16).toUpperCase()).join('');
                scrambleText += `[DECRYPT] 0x${hexLine}<br>`;
            }
            decryptTicker.innerHTML = scrambleText;
        }, 60);

        // 3. Finalize scan and render interactive breach cards
        setTimeout(() => {
            clearInterval(phraseInterval);
            clearInterval(tickerInterval);
            resultsList.innerHTML = ''; // Clear scrambler

            const breaches = generateBreachData(query);

            breaches.forEach((breach, idx) => {
                const card = document.createElement('div');
                card.className = "dw-leak-card";
                card.style.animationDelay = `${idx * 0.15}s`;
                card.innerHTML = `
                    <div class="dw-leak-header">
                        <span class="dw-source"><i class="fa-solid fa-mask"></i> ${breach.source}</span>
                        <span class="dw-date">${breach.date}</span>
                    </div>
                    <div class="dw-leak-detail">
                        <strong style="color:var(--text);">${breach.desc}</strong>
                        <p style="margin-top:8px; color:rgba(230, 241, 255, 0.7); font-family:'Fira Code', monospace; font-size:11px; line-height:1.5;">
                            ${breach.detail}
                        </p>
                    </div>
                `;
                resultsList.appendChild(card);
            });

            // Re-bind hover logic for masked tokens (though standard CSS does it, JS makes it extremely smooth)
            const maskedSpans = resultsList.querySelectorAll('.dw-masked');
            maskedSpans.forEach(span => {
                span.addEventListener('mouseenter', () => {
                    span.style.textShadow = 'none';
                    span.style.color = 'var(--danger)';
                    span.style.background = 'rgba(255, 107, 107, 0.15)';
                });
                span.addEventListener('mouseleave', () => {
                    span.style.textShadow = '0 0 8px rgba(255, 255, 255, 0.8)';
                    span.style.color = 'transparent';
                    span.style.background = '#222';
                });
            });

            window.addTimelineLog(`Dark Web scan finalized. ${breaches.length} threat breach signatures identified.`);
            window.showStatusOverlay("Scan Finished", `${breaches.length} compromised records retrieved.`, 1200);

            // Dynamically increment global threats if searching a real incident
            if (window.updateActiveThreatsCount) {
                window.updateActiveThreatsCount(1);
            }

        }, 2200);
    });
});

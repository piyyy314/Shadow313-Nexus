// --- SENTINELOS Blockchain Evidence Verification System ---

(() => {
    let blockchainLedger = [];
    const blockListWrapper = document.getElementById('ledger-blocks-wrapper');
    const btnSealBlock = document.getElementById('btn-bc-mine');
    const btnVerifyLedger = document.getElementById('btn-bc-verify');
    
    // Core Block Class definition
    class Block {
        constructor(index, timestamp, incidentData, prevHash) {
            this.index = index;
            this.timestamp = timestamp;
            this.incidentData = incidentData;
            this.prevHash = prevHash;
            this.nonce = 0;
            this.hash = this.calculateHash();
        }

        calculateHash() {
            // Simple robust string-based hash simulating SHA-256
            const rawStr = this.index + this.timestamp + JSON.stringify(this.incidentData) + this.prevHash + this.nonce;
            let hashVal = 0;
            for (let i = 0; i < rawStr.length; i++) {
                const char = rawStr.charCodeAt(i);
                hashVal = ((hashVal << 5) - hashVal) + char;
                hashVal = hashVal & hashVal; // Convert to 32bit integer
            }
            // Map integer to standard robust SHA256 length string
            const hex = Math.abs(hashVal).toString(16).padEnd(8, 'e') + 
                        Math.abs(hashVal * 31).toString(16).padEnd(8, 'f') +
                        Math.abs(hashVal * 97).toString(16).padEnd(8, 'a') +
                        Math.abs(hashVal * 127).toString(16).padEnd(8, 'b');
            return "0000" + hex.substring(4, 64); // Prefix 4 zeros to represent PoW solution
        }

        mineBlock(difficulty = 2) {
            const target = Array(difficulty + 1).join("0");
            while (this.hash.substring(0, difficulty) !== target) {
                this.nonce++;
                this.hash = this.calculateHash();
            }
        }
    }

    // Prepopulate ledger with genesis block
    const initBlockchainLedger = () => {
        blockchainLedger = [];
        
        // Genesis block
        const genesis = new Block(
            0,
            "2026-05-21T01:10:00",
            { desc: "Genesis Root Entropy Seed", hash: "A9F8E3C2B1D0E9F" },
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        genesis.hash = "0000a89f26cd398e09fbc751842831bb219800fc4ea120e8b15d0fc389bde009";
        
        blockchainLedger.push(genesis);
        renderLedgerBlocks();
    };

    const renderLedgerBlocks = () => {
        if (!blockListWrapper) return;
        blockListWrapper.innerHTML = "";

        blockchainLedger.forEach((block, idx) => {
            const card = document.createElement('div');
            card.className = "block-card verified";
            card.id = `block-card-${block.index}`;
            card.innerHTML = `
                <div class="block-header">
                    <span class="block-index">BLOCK #${block.index}</span>
                    <span class="block-badge" id="block-badge-${block.index}">SECURE</span>
                </div>
                <div class="block-body font-mono">
                    <div><strong>Timestamp:</strong> ${block.timestamp}</div>
                    <div><strong>Data:</strong> ${block.incidentData.desc}</div>
                    <div style="margin-top: 4px; word-break: break-all;"><strong>Hash:</strong> <span class="hash-text" id="hash-text-${block.index}">${block.hash}</span></div>
                    <div style="word-break: break-all;"><strong>Prev:</strong> <span style="opacity: 0.6;">${block.prevHash}</span></div>
                    <div style="margin-top: 8px; display:flex; justify-content: space-between; align-items:center;">
                        <span><strong>Nonce:</strong> ${block.nonce}</span>
                        <button class="btn btn-secondary btn-sm text-red" onclick="window.tamperBlock(${block.index})" style="padding: 2px 6px; font-size: 8px;">🔨 Tamper</button>
                    </div>
                </div>
            `;
            blockListWrapper.appendChild(card);
        });
    };

    // Mine new block
    if (btnSealBlock) {
        btnSealBlock.addEventListener('click', () => {
            const incidentDesc = document.getElementById('txt-bc-incident').value.trim();
            const evidenceHash = document.getElementById('txt-bc-evidence').value.trim();
            const feedbackBox = document.getElementById('mining-feedback-box');

            if (!incidentDesc || !evidenceHash) {
                alert("Please enter incident description and evidence parameters.");
                return;
            }

            feedbackBox.style.display = 'block';

            // Simulate CPU hashing thread nonces
            let nonceVal = 0;
            const logBox = feedbackBox.querySelector('span');
            
            const mineInterval = setInterval(() => {
                nonceVal += 12;
                logBox.textContent = `Solving PoW Nonce target [Nonce: ${nonceVal}]... Hash: 00${Math.random().toString(36).substring(2, 10).toUpperCase()}`;
            }, 60);

            setTimeout(() => {
                clearInterval(mineInterval);
                feedbackBox.style.display = 'none';

                // Instantiate real Block
                const lastBlock = blockchainLedger[blockchainLedger.length - 1];
                const newIdx = lastBlock.index + 1;
                const time = new Date().toISOString();
                
                const newBlock = new Block(
                    newIdx,
                    time,
                    { desc: incidentDesc, hash: evidenceHash },
                    lastBlock.hash
                );

                // Compute real simulated difficulty
                newBlock.mineBlock(4);
                
                blockchainLedger.push(newBlock);
                renderLedgerBlocks();

                // Clear input form
                document.getElementById('txt-bc-incident').value = "";
                document.getElementById('txt-bc-evidence').value = "";

                window.addTimelineLog(`Incident block #${newIdx} successfully mined. Hash: ${newBlock.hash.substring(0, 10)}... committed.`);
                window.showStatusOverlay("Evidence Sealed", `Block #${newIdx} securely added to hyperledger`, 1200);
            }, 1500);
        });
    }

    // Ledger Validation traversal
    if (btnVerifyLedger) {
        btnVerifyLedger.addEventListener('click', () => {
            let chainCorrupted = false;
            
            // Loop through block pointers validation
            for (let i = 1; i < blockchainLedger.length; i++) {
                const current = blockchainLedger[i];
                const prev = blockchainLedger[i-1];

                const cardEl = document.getElementById(`block-card-${current.index}`);
                const badgeEl = document.getElementById(`block-badge-${current.index}`);

                // Check recalculations matches
                const recalculatedHash = current.calculateHash();
                
                if (current.hash !== recalculatedHash || current.prevHash !== prev.hash) {
                    chainCorrupted = true;
                    if (cardEl) {
                        cardEl.className = "block-card tampered";
                    }
                    if (badgeEl) {
                        badgeEl.textContent = "CORRUPTED";
                    }
                } else {
                    if (cardEl) {
                        cardEl.className = "block-card verified";
                    }
                    if (badgeEl) {
                        badgeEl.textContent = "VERIFIED";
                    }
                }
            }

            if (chainCorrupted) {
                window.showStatusOverlay("Ledger Audit FAILED", "Warning: Mismatched block links found. Chain compromised!", 1800);
                window.addTimelineLog("Critical Warning: Ledger validation audit failed. Discrepancy identified in forensic block link.");
            } else {
                window.showStatusOverlay("Ledger Audit PASSED", "All blocks verified. Evidence chain immutable & secure.", 1500);
                window.addTimelineLog("Ledger verification audit completed successfully. Forensic records verified immune.");
            }
        });
    }

    // Interactive Tamper simulator global callback
    window.tamperBlock = (index) => {
        const block = blockchainLedger.find(b => b.index === index);
        if (block) {
            // Edit data inside memory block representation without solving nonce re-mine
            block.incidentData.desc = "[TAMPERED DATA ENTRY] " + block.incidentData.desc;
            
            // Render mismatch
            const hashTextEl = document.getElementById(`hash-text-${index}`);
            if (hashTextEl) {
                hashTextEl.textContent = "89A2BFD9E... [Corrupt recalculations mismatch]";
                hashTextEl.classList.add('text-red');
            }

            const badgeEl = document.getElementById(`block-badge-${index}`);
            if (badgeEl) {
                badgeEl.textContent = "TAMPERED";
                badgeEl.style.color = "var(--danger)";
            }

            window.addTimelineLog(`System Warning: Unauthorized raw access edit recorded on memory block #${index}. Ledger integrity flag raised.`);
            window.showStatusOverlay("Block Tampered", `Block #${index} payload modified. Run audit to trace impact.`, 1200);
        }
    };

    // Prepopulate Genesis blocks
    initBlockchainLedger();

})();

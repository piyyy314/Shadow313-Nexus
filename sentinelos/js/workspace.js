// --- SENTINELOS Collaborative Security Workspace ---

(() => {
    // 1. Interactive Terminal Shell simulator
    const termScreen = document.getElementById('terminal-screen');
    const termInput = document.getElementById('terminal-input');
    const cursorLine = document.getElementById('terminal-cursor-line');

    window.initWorkspaceView = () => {
        if (termInput) {
            termInput.focus();
            
            // Re-focus on terminal container click
            termScreen.addEventListener('click', () => {
                termInput.focus();
            });
        }
    };

    if (termInput) {
        termInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                const cmd = termInput.value.trim().toLowerCase();
                termInput.value = "";
                
                if (cmd) {
                    executeTerminalCommand(cmd);
                }
            }
        });
    }

    const appendTermLine = (text, isHtml = false) => {
        if (!termScreen || !cursorLine) return;
        const line = document.createElement('div');
        line.className = 'term-line';
        if (isHtml) {
            line.innerHTML = text;
        } else {
            line.textContent = text;
        }
        termScreen.insertBefore(line, cursorLine);
        termScreen.scrollTop = termScreen.scrollHeight;
    };

    const executeTerminalCommand = (rawCmd) => {
        // Echo input command back first - build safely to avoid XSS
        if (termScreen) {
            const echoLine = document.createElement('div');
            echoLine.className = 'term-line';
            const prompt = document.createElement('span');
            prompt.className = 'prompt';
            prompt.textContent = 'sentinel@core:~$';
            echoLine.appendChild(prompt);
            echoLine.appendChild(document.createTextNode(' ' + rawCmd));
            if (cursorLine) {
                termScreen.insertBefore(echoLine, cursorLine);
            } else {
                termScreen.appendChild(echoLine);
            }
            termScreen.scrollTop = termScreen.scrollHeight;
        }
        
        const args = rawCmd.split(' ');
        const cmd = args[0];

        const commands = {
            'help': () => {
                appendTermLine("Available Cryptographic routines:");
                appendTermLine("  scan       - Run quick local subgrid vulnerability audit sweeps");
                appendTermLine("  threats    - Summarize predictive geolocated threat targets");
                appendTermLine("  decrypt    - Initialize Kyber MLWE ciphertext solver matrix");
                appendTermLine("  playbook   - Run automated ransomware containment flowchecks");
                appendTermLine("  clear      - Clear terminal screen buffers");
            },
            'clear': () => {
                const lines = termScreen.querySelectorAll('.term-line');
                lines.forEach(l => {
                    if (l !== cursorLine) termScreen.removeChild(l);
                });
            },
            'scan': () => {
                appendTermLine("Initiating Local Subgrid Audit...");
                appendTermLine("Scanning open receptors for Port range 1-1024...");
                setTimeout(() => {
                    appendTermLine("  -> Port 22/tcp  [SSH]     - FILTERED (Secure Shield)");
                    appendTermLine("  -> Port 80/tcp  [HTTP]    - OPEN (Mitigated decs)");
                    appendTermLine("  -> Port 443/tcp [HTTPS]   - OPEN (SSL-TLS 1.3 verify)");
                    appendTermLine("  -> Port 3306/tcp [MySQL]  - TRAPPED (Deception SCADA)");
                    appendTermLine("Vulnerability Sweep finished. Threat level: 0% risk.");
                }, 1000);
            },
            'threats': () => {
                appendTermLine("Querying Predictive AI databases...");
                appendTermLine("Active geolocated attacks mapping: [0 critical threat points detected]");
                appendTermLine("Receivers sync metrics: Entropy Frequency 4.88 GHz - Sync Sync Sync.");
            },
            'decrypt': () => {
                appendTermLine("Kyber lattice solver standing by. Head over to the Quantum page to paste matrices.");
            },
            'playbook': () => {
                appendTermLine("[PLAYBOOK] Isolating infected subnet G-3... SUCCESS.");
                appendTermLine("[PLAYBOOK] Extracting volatile volatile forensic RAM logs... DONE.");
                appendTermLine("[PLAYBOOK] Rotating lattice certificates... SEALED.");
                appendTermLine("[PLAYBOOK] Evidence ledger hashes committed. Infrastructure healed.");
            }
        };

        if (commands[cmd]) {
            commands[cmd]();
        } else {
            appendTermLine(`Command not found: '${cmd}'. Type 'help' to review secure platform routines.`);
        }
    };

    // 2. Collaborative Operations Chatroom
    const chatMessages = document.getElementById('chat-messages');
    const chatInput = document.getElementById('chat-input');
    const btnSend = document.getElementById('btn-chat-send');

    const appendChatMessage = (author, avatar, text, isUser = false) => {
        if (!chatMessages) return;
        const msg = document.createElement('div');
        msg.className = `chat-message ${isUser ? 'user-member' : 'agent-ai'}`;
        
        const avatarSpan = document.createElement('span');
        avatarSpan.className = 'avatar';
        avatarSpan.textContent = avatar;
        const authorDiv = document.createElement('div');
        authorDiv.className = 'msg-author';
        authorDiv.textContent = author;
        const textDiv = document.createElement('div');
        textDiv.className = 'msg-text';
        textDiv.textContent = text;
        const bubbleDiv = document.createElement('div');
        bubbleDiv.className = 'msg-bubble';
        bubbleDiv.appendChild(authorDiv);
        bubbleDiv.appendChild(textDiv);
        msg.appendChild(avatarSpan);
        msg.appendChild(bubbleDiv);
        chatMessages.appendChild(msg);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    };

    const triggerChatSend = () => {
        const text = chatInput.value.trim();
        if (!text) return;
        
        chatInput.value = "";
        
        // Append user chat message
        appendChatMessage("Admin", "👤", text, true);
        
        // Formulate AI contextual replies
        setTimeout(() => {
            const query = text.toLowerCase();
            let reply = "I am mapping that query to active SentinelOS telemetry. Let me know if you would like me to trigger an automated containment playbook.";
            
            if (query.includes('scan') || query.includes('vuln')) {
                reply = "Vulnerability sweeps are active. Let me know if you want me to run a deep scan CVE index correlation on target IP: `192.168.100.45`.";
            } else if (query.includes('threat') || query.includes('attack')) {
                reply = "We are currently mitigating geolocated threat targets safely. The SCADA decoy is trapped and active. Security health is 100% immune.";
            } else if (query.includes('honeypot') || query.includes('decoy')) {
                reply = "Honeypots SCADA / SSH deployed successfully. We are tracking hacker metadata inside the entrapment log shells.";
            }
            
            appendChatMessage("Nova-AI", "🤖", reply, false);
        }, 1000);
    };

    if (btnSend) {
        btnSend.addEventListener('click', triggerChatSend);
    }
    if (chatInput) {
        chatInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') triggerChatSend();
        });
    }

})();

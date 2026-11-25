// --- SENTINELOS Collaborative Security Workspace (DEMONSTRATION MODE) ---

(() => {
    const termScreen = document.getElementById('terminal-screen');
    const termInput = document.getElementById('terminal-input');
    const cursorLine = document.getElementById('terminal-cursor-line');

    window.initWorkspaceView = () => {
        if (!termInput) return;
        termInput.focus();
        if (termScreen) {
            termScreen.addEventListener('click', () => termInput.focus(), { once: true });
        }
    };

    const appendTermLine = (text) => {
        if (!termScreen || !cursorLine) return;
        const line = document.createElement('div');
        line.className = 'term-line';
        line.textContent = text;
        termScreen.insertBefore(line, cursorLine);
        termScreen.scrollTop = termScreen.scrollHeight;
    };

    const executeTerminalCommand = (rawCommand) => {
        if (termScreen) {
            const echoLine = document.createElement('div');
            echoLine.className = 'term-line';
            const prompt = document.createElement('span');
            prompt.className = 'prompt';
            prompt.textContent = 'sentinel@demo:~$';
            echoLine.appendChild(prompt);
            echoLine.appendChild(document.createTextNode(' ' + rawCommand));
            termScreen.insertBefore(echoLine, cursorLine || null);
            termScreen.scrollTop = termScreen.scrollHeight;
        }

        const command = rawCommand.split(/\s+/, 1)[0];
        const commands = {
            help: () => {
                appendTermLine('DEMONSTRATION COMMANDS — no host or network actions are performed:');
                appendTermLine('  scan       - Display illustrative sample scan output');
                appendTermLine('  threats    - Display illustrative threat sample');
                appendTermLine('  decrypt    - Explain the local cryptography demo');
                appendTermLine('  playbook   - Preview a response sequence without executing it');
                appendTermLine('  clear      - Clear terminal screen buffers');
            },
            clear: () => {
                if (!termScreen) return;
                termScreen.querySelectorAll('.term-line').forEach((line) => {
                    if (line !== cursorLine) line.remove();
                });
            },
            scan: () => {
                appendTermLine('[DEMO] No target was contacted and no port scan was run.');
                appendTermLine('[SAMPLE] Example: TCP/22 filtered; TCP/80 open; TCP/443 open.');
                appendTermLine('[DEMO] No vulnerability assessment or risk score was produced.');
            },
            threats: () => {
                appendTermLine('[DEMO] No threat-intelligence feed is connected.');
                appendTermLine('[SAMPLE] Threat map and prediction values are illustrative only.');
                appendTermLine('[DEMO] No hosts, IP addresses, or attack sources are being tracked.');
            },
            decrypt: () => {
                appendTermLine('[DEMO] Cryptography examples are educational only.');
                appendTermLine('[DEMO] No ciphertext, key, credential, or protected data was processed.');
            },
            playbook: () => {
                appendTermLine('[DEMO] Response playbook preview only; no action was executed.');
                appendTermLine('[NOT CONFIGURED] Network isolation adapter.');
                appendTermLine('[NOT CONFIGURED] Forensic collection adapter.');
                appendTermLine('[NOT CONFIGURED] Credential rotation adapter.');
                appendTermLine('[NOT CONFIGURED] Evidence signing and persistence adapter.');
            },
        };

        if (commands[command]) {
            commands[command]();
        } else {
            appendTermLine(`Unknown demo command: '${command}'. Type 'help' for available demonstrations.`);
        }
    };

    if (termInput) {
        termInput.addEventListener('keydown', (event) => {
            if (event.key === 'Enter') {
                const command = termInput.value.trim().toLowerCase();
                termInput.value = '';
                if (command) executeTerminalCommand(command);
            }
        });
    }

    const chatMessages = document.getElementById('chat-messages');
    const chatInput = document.getElementById('chat-input');
    const sendButton = document.getElementById('btn-chat-send');

    const appendChatMessage = (author, avatar, text, isUser = false) => {
        if (!chatMessages) return;
        const message = document.createElement('div');
        message.className = `chat-message ${isUser ? 'user-member' : 'agent-ai'}`;

        const avatarSpan = document.createElement('span');
        avatarSpan.className = 'avatar';
        avatarSpan.textContent = avatar;

        const authorDiv = document.createElement('div');
        authorDiv.className = 'msg-author';
        authorDiv.textContent = author;

        const textDiv = document.createElement('div');
        textDiv.className = 'msg-text';
        textDiv.textContent = text;

        const bubble = document.createElement('div');
        bubble.className = 'msg-bubble';
        bubble.append(authorDiv, textDiv);
        message.append(avatarSpan, bubble);
        chatMessages.appendChild(message);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    };

    const triggerChatSend = () => {
        if (!chatInput) return;
        const text = chatInput.value.trim();
        if (!text) return;
        chatInput.value = '';
        appendChatMessage('Admin', '👤', text, true);

        const query = text.toLowerCase();
        let response = 'This is a browser-only demonstration. No live telemetry, threat feed, or automated response service is connected.';
        if (query.includes('scan') || query.includes('vuln')) {
            response = 'DEMO ONLY: I cannot run a vulnerability scan from this workspace. No target was contacted and no CVE correlation was performed.';
        } else if (query.includes('threat') || query.includes('attack')) {
            response = 'DEMO ONLY: No threat feed is connected. No attack is being mitigated, no decoy is active, and no security-immunity claim can be made.';
        } else if (query.includes('honeypot') || query.includes('decoy')) {
            response = 'NOT CONFIGURED: No honeypot process or SCADA/SSH listener was started. This interface only illustrates the workflow.';
        } else if (query.includes('contain') || query.includes('playbook')) {
            response = 'NOT CONFIGURED: The response adapters are not connected. No host isolation, process termination, credential rotation, or forensic collection was attempted.';
        }

        window.setTimeout(() => {
            appendChatMessage('Nova-AI Demo', '🤖', response, false);
        }, 250);
    };

    if (sendButton) sendButton.addEventListener('click', triggerChatSend);
    if (chatInput) {
        chatInput.addEventListener('keydown', (event) => {
            if (event.key === 'Enter') triggerChatSend();
        });
    }
})();

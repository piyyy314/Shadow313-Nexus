// --- SENTINELOS Heuristic Malware Sandbox & AI Disassembler ---

document.addEventListener('DOMContentLoaded', () => {
    const presetButtons = document.querySelectorAll('.btn-preset');
    const txtBinary = document.getElementById('txt-sb-binary');
    const btnScan = document.getElementById('btn-sb-disassemble');
    const sbGrade = document.getElementById('sb-grade');
    const sbScore = document.getElementById('sb-threat-score');
    const screen = document.getElementById('sb-disassembly-screen');

    if (!txtBinary || !btnScan || !sbGrade || !sbScore || !screen) return;

    // Binary hex preset signatures
    const presets = {
        worm: "89 E5 31 C0 50 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 50 89 E2 53 89 E1 B0 0B CD 80",
        safe: "4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40"
    };

    // Swap presets dynamically and alter active class
    presetButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            presetButtons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            const presetKey = btn.getAttribute('data-preset');
            if (presets[presetKey]) {
                txtBinary.value = presets[presetKey];
            }
        });
    });

    // Heuristic analysis templates
    const wormAsm = [
        { addr: "0x00008048", op: "XOR", args: "EAX, EAX", comment: "; Clear registers base value", dangerous: false },
        { addr: "0x0000804A", op: "PUSH", args: "EAX", comment: "; Null boundary for stack", dangerous: false },
        { addr: "0x0000804B", op: "PUSH", args: "0x68732f2f", comment: "; Shellcode string push: '//sh'", dangerous: true },
        { addr: "0x00008050", op: "PUSH", args: "0x6e69622f", comment: "; Shellcode string push: '/bin'", dangerous: true },
        { addr: "0x00008055", op: "MOV", args: "EBX, ESP", comment: "; Capture shell command string address", dangerous: false },
        { addr: "0x00008057", op: "MOV", args: "AL, 0x0B", comment: "; Register sys_execve call target", dangerous: false },
        { addr: "0x00008059", op: "INT", args: "0x80", comment: "; FORCING EXECUTIVE SYSTEM LEVEL SHELL!", dangerous: true },
        { addr: "0x0000805B", op: "HLT", args: "", comment: "; Halt current runner block", dangerous: false }
    ];

    const safeAsm = [
        { addr: "0x00401000", op: "MOV", args: "EAX, 0x01", comment: "; Retrieve system identity header", dangerous: false },
        { addr: "0x00401005", op: "ADD", args: "EAX, ECX", comment: "; Standard arithmetic index offset", dangerous: false },
        { addr: "0x00401007", op: "MOV", args: "[ESP+4], EAX", comment: "; Buffer output parameters register", dangerous: false },
        { addr: "0x0040100A", op: "RET", args: "", comment: "; Return workflow execution flow", dangerous: false }
    ];

    // Trigger visual disassembly sweep
    btnScan.addEventListener('click', () => {
        const hexInput = txtBinary.value.trim().toUpperCase();
        if (!hexInput) {
            window.showStatusOverlay("Scan Failed", "No executable hex payload detected.", 1200);
            return;
        }

        // 1. Initial State: Clear output and trigger logs
        screen.innerHTML = '';
        window.showStatusOverlay("Analyzing Payload", "Executing heuristics opcode tracing...", 1200);
        window.addTimelineLog("SANDBOX INIT: Analyzing pasted binary hex structures inside enclave sandbox.");

        // Print initial scanner indicators
        const diagLines = [
            "[SANDBOX] Creating zero-knowledge hypervisor isolation box...",
            "[SANDBOX] Indexing payload signature parameters...",
            "[SANDBOX] Parsing opcode registers control flow..."
        ];

        diagLines.forEach((line, idx) => {
            const row = document.createElement('div');
            row.style.color = 'var(--text-muted)';
            row.style.padding = '4px 0';
            row.style.animation = 'fade-in 0.3s ease forwards';
            row.style.animationDelay = `${idx * 0.2}s`;
            row.textContent = line;
            screen.appendChild(row);
        });

        // 2. Load instructions map sequentially
        setTimeout(() => {
            screen.innerHTML = ''; // Clear loading sequences
            
            // Check if it is the dangerous worm signature
            const isWorm = hexInput.includes("89 E5") || hexInput.includes("CD 80") || hexInput.length > 50;
            const asmInstructions = isWorm ? wormAsm : safeAsm;

            asmInstructions.forEach((inst, idx) => {
                const row = document.createElement('div');
                row.className = `asm-line${inst.dangerous ? ' dangerous' : ''}`;
                row.style.animation = 'fade-in 0.3s ease forwards';
                row.style.animationDelay = `${idx * 0.08}s`;
                
                row.innerHTML = `
                    <span class="asm-addr">${inst.addr}</span>
                    <span class="asm-op">${inst.op}</span>
                    <span class="asm-args">${inst.args}</span>
                    <span class="asm-comment">${inst.comment}</span>
                `;
                screen.appendChild(row);
            });

            // 3. Update Risk Scorecard metrics
            if (isWorm) {
                sbGrade.textContent = "CRITICAL RISK";
                sbGrade.className = "val danger";
                sbScore.textContent = `${90 + Math.floor(Math.random() * 8)} / 100`;
                
                window.addTimelineLog("MALWARE CRITICAL ALERT: Heuristic Sandbox detected severe buffer overflow shellcode!");
                window.showStatusOverlay("Malware Detected", "Instruction scan indicates executive shell hijack exploits.", 1800);
                
                // Add threat alert to the global dashboard if configured
                if (window.updateActiveThreatsCount) {
                    window.updateActiveThreatsCount(1);
                }
            } else {
                sbGrade.textContent = "SAFE UTILITY";
                sbGrade.className = "val";
                sbGrade.style.color = "var(--success)";
                sbGrade.style.textShadow = "0 0 8px rgba(29, 209, 161, 0.4)";
                sbScore.textContent = `${2 + Math.floor(Math.random() * 3)} / 100`;
                
                window.addTimelineLog("SANDBOX COMPLETED: Heuristic scan reports clean binary signature. No threat detected.");
                window.showStatusOverlay("Payload Secure", "Assembly instruction mappings verified healthy.", 1500);
            }

        }, 1500);
    });

    // Expose view initialization hook to reset states if needed
    window.initSandboxView = () => {
        screen.innerHTML = '<div style="color:var(--text-muted); font-style:italic;">Upload executable preset payloads or paste custom opcodes above and trigger scan.</div>';
        sbGrade.textContent = "WAITING SCAN";
        sbGrade.className = "val";
        sbGrade.style.color = "var(--text-muted)";
        sbGrade.style.textShadow = "none";
        sbScore.textContent = "-- / 100";
    };

    // Load initial view state
    window.initSandboxView();
});

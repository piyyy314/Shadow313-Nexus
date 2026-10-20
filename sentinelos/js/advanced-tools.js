// --- SENTINELOS Next-Gen Experimental Tools Logic ---

(() => {
    // Shared state
    let activeAnimIds = {};

    const cancelViewAnims = () => {
        Object.values(activeAnimIds).forEach(id => cancelAnimationFrame(id));
        activeAnimIds = {};
    };

    // ==========================================================
    // 1. PQC SCANNER (Matrix Waterfall)
    // ==========================================================
    window.initPqcView = () => {
        cancelViewAnims();
        const canvas = document.getElementById('pqc-matrix-canvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        
        const resize = () => {
            canvas.width = canvas.parentElement.clientWidth;
            canvas.height = canvas.parentElement.clientHeight || 300;
        };
        resize();
        window.addEventListener('resize', resize);

        const chars = '01ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('');
        const fontSize = 14;
        const columns = canvas.width / fontSize;
        const drops = [];
        for (let x = 0; x < columns; x++) drops[x] = 1;

        const draw = () => {
            ctx.fillStyle = 'rgba(10, 15, 30, 0.1)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);

            ctx.fillStyle = '#48dbfb'; // PQC Blue
            ctx.font = fontSize + 'px monospace';

            for (let i = 0; i < drops.length; i++) {
                const text = chars[Math.floor(Math.random() * chars.length)];
                ctx.fillText(text, i * fontSize, drops[i] * fontSize);

                if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                    drops[i] = 0;
                }
                drops[i]++;
            }
            activeAnimIds['pqc'] = requestAnimationFrame(draw);
        };
        draw();
        
        // Button Logic
        document.querySelectorAll('.btn-migrate').forEach(btn => {
            btn.onclick = function() {
                this.classList.replace('btn-primary', 'btn-secondary');
                this.textContent = 'MIGRATED TO KYBER';
                this.disabled = true;
                const timeEl = this.parentElement.querySelector('.crack-val');
                timeEl.textContent = 'IMMUNE';
                timeEl.classList.replace('text-red', 'text-green');
                if (window.showStatusOverlay) {
                    window.showStatusOverlay("PQC MIGRATION", "Target encryption successfully upgraded to Kyber-1024.", 1500);
                }
            };
        });
    };

    // ==========================================================
    // 2. AUTONOMOUS SWARM
    // ==========================================================
    window.initSwarmView = () => {
        cancelViewAnims();
        const canvas = document.getElementById('swarm-canvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        
        const resize = () => {
            canvas.width = canvas.parentElement.clientWidth;
            canvas.height = canvas.parentElement.clientHeight || 400;
        };
        resize();
        window.addEventListener('resize', resize);

        let agents = [];
        let targets = [];
        let isDeployed = false;

        class Boid {
            constructor(x, y) {
                this.x = x;
                this.y = y;
                this.vx = (Math.random() - 0.5) * 4;
                this.vy = (Math.random() - 0.5) * 4;
            }
            update() {
                // Seek target if deployed
                if (isDeployed && targets.length > 0) {
                    const t = targets[0];
                    const dx = t.x - this.x;
                    const dy = t.y - this.y;
                    const dist = Math.hypot(dx, dy);
                    if (dist > 30) {
                        this.vx += (dx / dist) * 0.1;
                        this.vy += (dy / dist) * 0.1;
                    }
                }
                
                // Add some noise
                this.vx += (Math.random() - 0.5) * 0.5;
                this.vy += (Math.random() - 0.5) * 0.5;

                // Speed limit
                const speed = Math.hypot(this.vx, this.vy);
                if (speed > 4) {
                    this.vx = (this.vx / speed) * 4;
                    this.vy = (this.vy / speed) * 4;
                }

                this.x += this.vx;
                this.y += this.vy;

                // Bounce bounds
                if (this.x < 0 || this.x > canvas.width) this.vx *= -1;
                if (this.y < 0 || this.y > canvas.height) this.vy *= -1;
            }
            draw() {
                ctx.fillStyle = '#00d4aa';
                ctx.beginPath();
                ctx.arc(this.x, this.y, 2, 0, Math.PI * 2);
                ctx.fill();
            }
        }

        // Initialize target
        targets.push({x: canvas.width/2, y: canvas.height/2});

        const draw = () => {
            ctx.fillStyle = 'rgba(10, 15, 30, 0.2)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);

            // Draw target
            if (targets.length > 0) {
                ctx.fillStyle = '#ff4757'; // Red anomaly
                ctx.beginPath();
                ctx.arc(targets[0].x, targets[0].y, 10 + Math.sin(Date.now()*0.005)*3, 0, Math.PI * 2);
                ctx.fill();
                
                // Pulse ring
                ctx.strokeStyle = `rgba(255, 71, 87, ${Math.abs(Math.cos(Date.now()*0.002))})`;
                ctx.lineWidth = 2;
                ctx.beginPath();
                ctx.arc(targets[0].x, targets[0].y, 20 + Math.abs(Math.sin(Date.now()*0.002)*10), 0, Math.PI * 2);
                ctx.stroke();
            }

            // Update and draw agents
            agents.forEach(a => {
                a.update();
                a.draw();
            });

            activeAnimIds['swarm'] = requestAnimationFrame(draw);
        };
        draw();

        document.getElementById('btn-deploy-swarm').onclick = () => {
            if (isDeployed) return;
            isDeployed = true;
            document.getElementById('swarm-status-log').textContent = "Swarm deployed. Encircling target anomaly...";
            
            // Spawn agents
            let spawned = 0;
            const spawnInterval = setInterval(() => {
                agents.push(new Boid(Math.random() * canvas.width, Math.random() * canvas.height));
                spawned++;
                document.getElementById('swarm-count').textContent = spawned;
                if (spawned >= 150) {
                    clearInterval(spawnInterval);
                    setTimeout(() => {
                        document.getElementById('swarm-status-log').textContent = "Target successfully isolated by defensive swarm.";
                        targets = [];
                        document.getElementById('swarm-threats').textContent = "0";
                    }, 3000);
                }
            }, 10);
        };
    };

    // ==========================================================
    // 3. DEEPFAKE ANALYZER
    // ==========================================================
    window.initDeepfakeView = () => {
        cancelViewAnims();
        const face = document.getElementById('df-face');
        const canvas = document.getElementById('df-audio-canvas');
        if (!face || !canvas) return;

        // Face rotation effect
        let rotY = 0;
        const faceLoop = () => {
            rotY = Math.sin(Date.now() * 0.001) * 20;
            face.style.transform = `rotateY(${rotY}deg) scale(0.9)`;
            activeAnimIds['df-face'] = requestAnimationFrame(faceLoop);
        };
        faceLoop();

        // Audio Waveform
        const ctx = canvas.getContext('2d');
        const resize = () => {
            canvas.width = canvas.parentElement.clientWidth;
            canvas.height = canvas.parentElement.clientHeight || 80;
        };
        resize();
        
        let isAnalyzing = false;
        
        const drawWave = () => {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            ctx.lineWidth = 2;
            ctx.strokeStyle = '#9b51e0';
            ctx.beginPath();
            
            const bars = 40;
            const spacing = canvas.width / bars;
            for(let i = 0; i < bars; i++) {
                let h = 5 + Math.random() * 10;
                if (isAnalyzing) h = 10 + Math.random() * 40;
                ctx.moveTo(i * spacing, canvas.height/2 - h);
                ctx.lineTo(i * spacing, canvas.height/2 + h);
            }
            ctx.stroke();
            activeAnimIds['df-wave'] = requestAnimationFrame(drawWave);
        };
        drawWave();

        document.getElementById('btn-df-analyze').onclick = function() {
            if (isAnalyzing) return;
            isAnalyzing = true;
            this.disabled = true;
            
            document.querySelector('.df-scan-overlay').style.height = '100%';
            document.getElementById('df-verdict').textContent = "Analyzing facial mesh & spectral frequencies...";
            document.getElementById('df-verdict').className = "df-verdict"; // reset color
            
            let progress = 0;
            const barInt = setInterval(() => {
                progress += 5;
                document.getElementById('df-lip-fill').textContent = progress + '%';
                document.getElementById('df-audio-fill').textContent = progress + '%';
                document.getElementById('df-prob').textContent = progress + '%';
                if (progress >= 94) {
                    clearInterval(barInt);
                    isAnalyzing = false;
                    document.getElementById('df-verdict').textContent = "⚠️ SYNTHETIC DEEPFAKE DETECTED (94% CONFIDENCE)";
                    document.getElementById('df-verdict').classList.add('text-red');
                    face.style.stroke = "#ff4757"; // Turn face red
                }
            }, 100);
        };
    };

    // ==========================================================
    // 4. RF SPECTRUM ANALYZER
    // ==========================================================
    window.initRfView = () => {
        cancelViewAnims();
        const canvas = document.getElementById('rf-radar-canvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        
        const resize = () => {
            canvas.width = canvas.parentElement.clientWidth;
            canvas.height = canvas.parentElement.clientHeight || 400;
        };
        resize();
        window.addEventListener('resize', resize);

        let angle = 0;
        let anomalies = [];
        let isSweeping = false;

        const draw = () => {
            ctx.fillStyle = 'rgba(10, 15, 30, 0.1)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            
            const cx = canvas.width / 2;
            const cy = canvas.height / 2;
            const radius = Math.min(cx, cy) - 20;

            // Draw grid
            ctx.strokeStyle = 'rgba(72, 219, 251, 0.2)';
            ctx.beginPath();
            ctx.arc(cx, cy, radius, 0, Math.PI * 2);
            ctx.arc(cx, cy, radius * 0.66, 0, Math.PI * 2);
            ctx.arc(cx, cy, radius * 0.33, 0, Math.PI * 2);
            ctx.stroke();

            // Draw crosshairs
            ctx.beginPath();
            ctx.moveTo(cx, cy - radius); ctx.lineTo(cx, cy + radius);
            ctx.moveTo(cx - radius, cy); ctx.lineTo(cx + radius, cy);
            ctx.stroke();

            // Draw sweep
            angle += 0.05;
            ctx.save();
            ctx.translate(cx, cy);
            ctx.rotate(angle);
            ctx.beginPath();
            ctx.moveTo(0, 0);
            ctx.arc(0, 0, radius, 0, -0.4, true);
            const grad = ctx.createRadialGradient(0, 0, 0, 0, 0, radius);
            grad.addColorStop(0, 'rgba(0, 212, 170, 0.8)');
            grad.addColorStop(1, 'rgba(0, 212, 170, 0)');
            ctx.fillStyle = grad;
            ctx.fill();
            ctx.restore();

            // Draw anomalies
            anomalies.forEach(a => {
                ctx.fillStyle = a.color;
                ctx.beginPath();
                ctx.arc(cx + Math.cos(a.angle) * (a.dist * radius), cy + Math.sin(a.angle) * (a.dist * radius), 4 + Math.sin(Date.now()*0.005)*2, 0, Math.PI*2);
                ctx.fill();
            });

            activeAnimIds['rf'] = requestAnimationFrame(draw);
        };
        draw();

        document.getElementById('btn-rf-sweep').onclick = () => {
            if(isSweeping) return;
            isSweeping = true;
            document.getElementById('rf-signal-list').innerHTML = `<li class="rf-item safe"><div class="rf-item-icon"><i class="fa-solid fa-router"></i></div><div class="rf-item-details"><span class="rf-name">Secure Gateway Alpha</span><span class="rf-freq">5.0 GHz · WPA3</span></div></li>`;
            
            setTimeout(() => {
                anomalies.push({angle: Math.random() * Math.PI * 2, dist: 0.6, color: '#ff4757'});
                const list = document.getElementById('rf-signal-list');
                const li = document.createElement('li');
                li.className = 'rf-item danger';
                li.innerHTML = `<div class="rf-item-icon text-red"><i class="fa-solid fa-tower-cell"></i></div><div class="rf-item-details"><span class="rf-name text-red">Rogue Stingray Interceptor</span><span class="rf-freq text-red">900 MHz · High Power</span></div>`;
                list.appendChild(li);
                
                if (window.showStatusOverlay) {
                    window.showStatusOverlay("RF ANOMALY", "Rogue cell tower detected near perimeter.", 2000);
                }
                isSweeping = false;
            }, 1500);
        };
    };

    // ==========================================================
    // 5. ZERO-TRUST MATRIX
    // ==========================================================
    window.initZtnaView = () => {
        const scene = document.getElementById('ztna-scene');
        if (!scene) return;
        scene.innerHTML = ''; // clear

        // Create isometric grid
        const grid = document.createElement('div');
        grid.className = 'ztna-grid';
        
        let nodes = [];
        for (let i = 0; i < 16; i++) {
            const node = document.createElement('div');
            node.className = 'ztna-node';
            // Connect lines
            if (i % 4 !== 3) {
                const linkH = document.createElement('div');
                linkH.className = 'ztna-link horizontal';
                node.appendChild(linkH);
            }
            if (i < 12) {
                const linkV = document.createElement('div');
                linkV.className = 'ztna-link vertical';
                node.appendChild(linkV);
            }
            
            node.onclick = function() {
                if (this.classList.contains('breached')) {
                    this.classList.add('shattered');
                    this.classList.remove('breached');
                    document.getElementById('ztna-logs').innerHTML += "<br>> Cryptographic air-gap applied to sector node.";
                }
            };
            
            grid.appendChild(node);
            nodes.push(node);
        }
        scene.appendChild(grid);

        document.getElementById('btn-ztna-breach').onclick = () => {
            const target = nodes[10]; // specific node
            target.classList.add('breached');
            document.getElementById('ztna-logs').innerHTML += "<br>> <span class='text-red'>WARNING: Unauthorized access attempt in sector 7.</span>";
        };

        document.getElementById('btn-ztna-reset').onclick = () => {
            nodes.forEach(n => { n.classList.remove('breached'); n.classList.remove('shattered'); });
            document.getElementById('ztna-logs').innerHTML = "> Matrix stable.";
        };
    };
})();

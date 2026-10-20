document.addEventListener('pywebviewready', () => {
    setInterval(updateStats, 2000);
});

async function updateStats() {
    try {
        const stats = await window.pywebview.api.get_system_stats();
        document.getElementById('cpu-stat').innerText = Math.round(stats.cpu) + "%";
        document.getElementById('ram-stat').innerText = Math.round(stats.ram) + "%";
    } catch(e) {}
}

function switchTab(viewId, navItem) {
    document.querySelectorAll('.nav li').forEach(li => li.classList.remove('active'));
    navItem.classList.add('active');

    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.getElementById('view-' + viewId).classList.add('active');
}

async function startScan(mode) {
    const btnQuick = document.getElementById('btn-quick');
    const btnFull = document.getElementById('btn-full');
    const grid = document.getElementById('findings-grid');
    const term = document.getElementById('terminal-output');
    
    btnQuick.disabled = true;
    btnFull.disabled = true;
    btnQuick.innerText = "SCANNING...";
    btnFull.innerText = "SCANNING...";
    
    grid.innerHTML = `<div class="card empty">Executing ${mode.toUpperCase()} scan... Check Logs tab.</div>`;
    term.innerText = `> Initializing ${mode.toUpperCase()} scan...\n`;

    switchTab('logs', document.querySelector('.nav li:nth-child(2)'));

    // Let the UI render the logs tab before Python locks up the thread
    setTimeout(async () => {
        try {
            const response = await window.pywebview.api.start_scan(mode);
            
            term.innerText += response.logs.join('\n');
            term.scrollTop = term.scrollHeight;
            
            const results = response.findings;
            
            document.getElementById('total-threats').innerText = results.length;
            const crit = results.filter(r => r.severity === "CRITICAL").length;
            document.getElementById('crit-threats').innerText = crit;

            if (results.length === 0) {
                grid.innerHTML = '<div class="card empty" style="color: #1DD1A1; border-color: #1DD1A1;">System Clean. No traces found.</div>';
            } else {
                grid.innerHTML = '';
                results.forEach(r => {
                    const div = document.createElement('div');
                    div.className = `card ${r.severity.toLowerCase()}`;
                    
                    div.style.cursor = "pointer";
                    div.title = "Click to open file location";
                    div.onclick = () => window.pywebview.api.open_folder(r.path);

                    div.innerHTML = `
                        <div class="category">${r.category} // ${r.severity}</div>
                        <div class="artifact">${r.artifact}</div>
                        <div class="path">${r.path}</div>
                        <div style="font-size: 10px; color: #8a8a99; font-family: monospace; margin-top: 4px; word-break: break-all;">Hash: ${r.hash || 'N/A'}</div>
                        <div class="timestamp">${r.timestamp}</div>
                    `;
                    grid.appendChild(div);
                });
            }
        } catch(e) {
            grid.innerHTML = `<div class="card empty" style="color: #ff2a2a;">Error: ${e}</div>`;
            term.innerText += `\nERROR: ${e}`;
        }

        btnQuick.innerText = "QUICK SCAN";
        btnFull.innerText = "FULL DRIVE SCAN";
        btnQuick.disabled = false;
        btnFull.disabled = false;
    }, 100);
}
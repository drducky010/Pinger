const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const HTML_FILE_PATH = path.join(__dirname, 'index.html');

// SET YOUR PASSWORD HERE (Change 'admin123' to whatever you want)
const ACCESS_PASSWORD = process.env.PING_PASSWORD || 'admin123';

const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Public Network Monitor</title>
    <style>
        body {
            background-color: #121212;
            color: #00ff00;
            font-family: 'Courier New', Courier, monospace;
            padding: 20px;
        }
        h1 {
            color: #ffffff;
            font-size: 24px;
            margin-bottom: 5px;
        }
        .controls {
            margin-bottom: 15px;
            background: #1e1e1e;
            padding: 10px;
            border-radius: 5px;
            border: 1px solid #333;
        }
        input, button {
            background: #000;
            color: #00ff00;
            border: 1px solid #00ff00;
            padding: 5px 10px;
            font-family: inherit;
            border-radius: 3px;
        }
        button:hover {
            background: #00ff00;
            color: #000;
            cursor: pointer;
        }
        #terminal {
            background-color: #000000;
            border: 1px solid #333;
            padding: 15px;
            height: 450px;
            overflow-y: scroll;
            border-radius: 5px;
            white-space: pre-wrap;
        }
        .time {
            color: #888;
        }
        .hidden { display: none !important; }
    </style>
</head>
<body>

    <div id="authArea" class="controls">
        <h3>🔑 Enter Password to Access Monitor</h3>
        <input type="password" id="passwordInput" placeholder="Password...">
        <button id="loginBtn">Connect</button>
    </div>

    <div id="monitorArea" class="hidden">
        <h1>Network Ping Monitor</h1>
        <div class="controls">
            <label for="targetIp">Target IP or Website: </label>
            <input type="text" id="targetIp" value="8.8.8.8">
            <button id="updateBtn">Change Target</button>
        </div>
        <div id="status">Connecting to ping stream...</div>
        <br>
        <div id="terminal"></div>
    </div>

    <script>
        const terminal = document.getElementById('terminal');
        const statusDiv = document.getElementById('status');
        const targetInput = document.getElementById('targetIp');
        const updateBtn = document.getElementById('updateBtn');
        const authArea = document.getElementById('authArea');
        const monitorArea = document.getElementById('monitorArea');
        const passwordInput = document.getElementById('passwordInput');
        const loginBtn = document.getElementById('loginBtn');
        
        let ws;

        loginBtn.onclick = () => {
            const pass = passwordInput.value;
            // Establish Secure WebSocket (wss://) if running on https cloud platform, or normal ws:// locally
            const protocol = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
            ws = new WebSocket(\`\${protocol}\${window.location.host}\`);

            ws.onopen = () => {
                // Send authentication payload first
                ws.send(JSON.stringify({ type: 'auth', password: pass }));
            };

            ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                
                if (data.type === 'auth_success') {
                    authArea.classList.add('hidden');
                    monitorArea.classList.remove('hidden');
                    statusDiv.innerHTML = "🟢 Connected. Monitoring live network...";
                    statusDiv.style.color = "#00ff00";
                    ws.send(JSON.stringify({ type: 'setTarget', target: targetInput.value }));
                } else if (data.type === 'auth_fail') {
                    alert("Incorrect Password!");
                    ws.close();
                } else if (data.log) {
                    const logEntry = document.createElement('div');
                    logEntry.innerHTML = \`<span class="time">[\${data.timestamp}]</span>\\n\${data.log}\\n\\n\`;
                    terminal.appendChild(logEntry);
                    terminal.scrollTop = terminal.scrollHeight;
                }
            };

            ws.onclose = () => {
                statusDiv.innerHTML = "🔴 Disconnected from ping stream.";
                statusDiv.style.color = "#ff0000";
            };
        };

        updateBtn.onclick = () => {
            if (ws && ws.readyState === WebSocket.OPEN) {
                terminal.innerHTML = ''; 
                ws.send(JSON.stringify({ type: 'setTarget', target: targetInput.value }));
            }
        };
    </script>
</body>
</html>`;

fs.writeFileSync(HTML_FILE_PATH, htmlContent, 'utf8');

app.get('/', (req, res) => {
    res.sendFile(HTML_FILE_PATH);
});

function isValidTarget(target) {
    return /^[a-zA-Z0-9.-]+$/.test(target);
}

function executePing(ws, target) {
    if (!isValidTarget(target)) {
        if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ timestamp: new Date().toLocaleTimeString(), log: "Invalid target address" }));
        }
        return;
    }
    const cmd = process.platform === 'win32' ? `ping -n 1 ${target}` : `ping -c 1 ${target}`;
    
    exec(cmd, (error, stdout, stderr) => {
        let output = stdout || stderr || "Ping failed";
        if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
                timestamp: new Date().toLocaleTimeString(),
                log: output.trim()
            }));
        }
    });
}

wss.on('connection', (ws) => {
    let currentTarget = '8.8.8.8';
    let intervalId = null;
    let isAuthenticated = false;

    ws.on('message', (message) => {
        const data = JSON.parse(message);
        
        // Handle login verification
        if (data.type === 'auth') {
            if (data.password === ACCESS_PASSWORD) {
                isAuthenticated = true;
                ws.send(JSON.stringify({ type: 'auth_success' }));
            } else {
                ws.send(JSON.stringify({ type: 'auth_fail' }));
            }
            return;
        }

        // Kick malicious drops that skip auth step
        if (!isAuthenticated) return ws.close();

        if (data.type === 'setTarget') {
            currentTarget = data.target;
            if (intervalId) clearInterval(intervalId);
            executePing(ws, currentTarget);
            intervalId = setInterval(() => executePing(ws, currentTarget), 1000);
        }
    });
    
    ws.on('close', () => {
        if (intervalId) clearInterval(intervalId);
    });
});

// Bind dynamically to whatever environment port Render provides, defaulting to 3000
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running successfully on port ${PORT}`);
});

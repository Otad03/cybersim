// Global State
const state = {
    mode: 'defense',
    systemHealth: 100,
    score: 0,
    isFirewallActive: false,
    isAntivirusActive: false,
    blockedIPs: []
};

// Enhanced tools configuration with categories
const tools = {
    defense: {
        'Network Security': [
            { id: 'firewall', name: 'Firewall', desc: 'Configure network firewall', icon: '🔥' },
            { id: 'vpn', name: 'VPN', desc: 'Secure VPN connection', icon: '🔒' },
            { id: 'ids', name: 'Intrusion Detection', desc: 'Monitor for intrusions', icon: '🚨' },
            { id: 'web-filter', name: 'Web Filter', desc: 'Block malicious sites', icon: '🌐' }
        ],
        'Endpoint Protection': [
            { id: 'antivirus', name: 'Antivirus', desc: 'Scan for malware', icon: '🦠' },
            { id: 'encryption', name: 'Encryption', desc: 'Encrypt sensitive data', icon: '🔐' },
            { id: 'endpoint-protection', name: 'Endpoint Security', desc: 'Protect devices', icon: '💻' },
            { id: 'patch', name: 'Patch Management', desc: 'Update system patches', icon: '🔧' }
        ],
        'Threat Detection': [
            { id: 'phishing', name: 'Phishing Detector', desc: 'Detect phishing attempts', icon: '🎣' },
            { id: 'siem', name: 'SIEM Dashboard', desc: 'Security monitoring', icon: '📊' },
            { id: 'honeypot', name: 'Honeypot', desc: 'Trap attackers', icon: '🍯' },
            { id: 'email-security', name: 'Email Security', desc: 'Email protection', icon: '📧' }
        ],
        'Data Protection': [
            { id: 'backup', name: 'Backup System', desc: 'Create data backups', icon: '💾' },
            { id: 'access-control', name: 'Access Control', desc: 'Manage permissions', icon: '🔑' },
            { id: 'cloud-security', name: 'Cloud Security', desc: 'Secure cloud infra', icon: '☁️' },
            { id: 'incident-response', name: 'Incident Response', desc: 'Handle incidents', icon: '🚨' }
        ]
    },
    attack: {
        'Web Application': [
            { id: 'sql-injection', name: 'SQL Injection', desc: 'Test SQL vulnerability', icon: '💉' },
            { id: 'xss', name: 'XSS Attack', desc: 'Test XSS vulnerability', icon: '⚡' },
            { id: 'api-security', name: 'API Security', desc: 'Test API vulnerabilities', icon: '🔌' },
            { id: 'zero-day', name: 'Zero-Day', desc: 'Exploit vulnerabilities', icon: '🎯' }
        ],
        'Network Attacks': [
            { id: 'port-scan', name: 'Port Scanner', desc: 'Scan network ports', icon: '🔍' },
            { id: 'dos', name: 'DoS Simulation', desc: 'Denial of service', icon: '💥' },
            { id: 'mitm', name: 'Man-in-Middle', desc: 'Intercept communications', icon: '👤' },
            { id: 'wireless-attack', name: 'Wireless Attack', desc: 'Compromise WiFi', icon: '📡' }
        ],
        'System Exploitation': [
            { id: 'password-crack', name: 'Password Cracker', desc: 'Test password strength', icon: '🔓' },
            { id: 'ransomware', name: 'Ransomware', desc: 'Simulate ransomware', icon: '🔒' },
            { id: 'cloud-penetration', name: 'Cloud Penetration', desc: 'Attack cloud infra', icon: '☁️' },
            { id: 'iot-hacking', name: 'IoT Hacking', desc: 'Compromise IoT devices', icon: '📱' }
        ],
        'Social Engineering': [
            { id: 'social-eng', name: 'Social Engineering', desc: 'Human vulnerabilities', icon: '🎭' },
            { id: 'mobile-security', name: 'Mobile Security', desc: 'Test mobile apps', icon: '📲' },
            { id: 'reverse-engineering', name: 'Reverse Engineering', desc: 'Analyze malware', icon: '🔍' },
            { id: 'forensics', name: 'Digital Forensics', desc: 'Analyze evidence', icon: '🔎' }
        ]
    }
};

// Quick actions configuration
const quickActions = {
    defense: [
        { name: 'Quick Scan', action: 'runQuickScan', icon: '⚡' },
        { name: 'Enable Firewall', action: 'enableFirewall', icon: '🔥' },
        { name: 'Check Status', action: 'checkStatus', icon: '📊' }
    ],
    attack: [
        { name: 'Port Scan', action: 'quickPortScan', icon: '🔍' },
        { name: 'Test Password', action: 'testPassword', icon: '🔓' },
        { name: 'SQL Test', action: 'testSQL', icon: '💉' }
    ]
};

// Tutorial Content
const tutorialContent = {
    overview: `
        <h3>Welcome to CyberSec Simulator!</h3>
        <p>This is a comprehensive cybersecurity training platform designed to help you learn both defensive and offensive security techniques in a safe, simulated environment.</p>
        
        <div class="success-box">
            <strong>🎯 Learning Objectives:</strong>
            <ul>
                <li>Understand common cyber threats and vulnerabilities</li>
                <li>Learn defensive security measures and best practices</li>
                <li>Explore offensive security techniques ethically</li>
                <li>Practice incident response and security analysis</li>
            </ul>
        </div>

        <h3>Getting Started</h3>
        <h4>1. Understanding the Interface</h4>
        <ul>
            <li><strong>System Health:</strong> Tracks your system's security status (0-100%). Successful defenses increase it, attacks decrease it.</li>
            <li><strong>Score:</strong> Earn points by completing security tasks and defending against threats.</li>
            <li><strong>Activity Log:</strong> View real-time logs of all security events and actions.</li>
            <li><strong>Terminal:</strong> Execute commands to interact with the system.</li>
            <li><strong>Browser Window:</strong> Visual interface for running security tools and simulations.</li>
        </ul>

        <h4>2. Two Primary Modes</h4>
        <ul>
            <li><strong>🛡️ Defense Mode:</strong> Learn to protect systems from attacks using firewalls, antivirus, encryption, and more.</li>
            <li><strong>⚔️ Attack Mode:</strong> Ethically test system vulnerabilities using penetration testing techniques.</li>
        </ul>

        <div class="tip-box">
            <strong>💡 Pro Tip:</strong> Start with Defense Mode to understand security fundamentals, then move to Attack Mode to learn how vulnerabilities are exploited.
        </div>

        <h3>Scoring System</h3>
        <ul>
            <li>Successful defense actions: +10 to +30 points</li>
            <li>Discovering vulnerabilities: +20 to +30 points</li>
            <li>Applying security patches: +30 points</li>
            <li>Ignoring warnings or disabling security: -10 points</li>
        </ul>

        <h3>Best Practices</h3>
        <ol>
            <li>Monitor your System Health regularly</li>
            <li>Check the Activity Log to understand what's happening</li>
            <li>Use the Terminal for quick status checks</li>
            <li>Try different tools to see how they work</li>
            <li>Learn from both successful and failed security tests</li>
        </ol>

        <div class="warning-box">
            <strong>⚠️ Ethical Notice:</strong> All techniques demonstrated here are for educational purposes only. Always practice cybersecurity ethically and legally.
        </div>
    `,
    
    defense: `
        <h3>🛡️ Defense Mode Tools</h3>
        <p>Learn to protect systems and networks from cyber threats using industry-standard defensive techniques.</p>

        <h3>🔥 Firewall Configuration</h3>
        <h4>What it does:</h4>
        <p>A firewall acts as a barrier between your network and potential threats, controlling incoming and outgoing traffic based on security rules.</p>
        
        <h4>How to use:</h4>
        <ol>
            <li>Click "Firewall Configuration" in the tools panel</li>
            <li>Enter an IP address to block (e.g., 192.168.1.100)</li>
            <li>Click "Block IP" to add it to your blocklist</li>
            <li>Toggle the firewall on/off using the enable button</li>
        </ol>

        <div class="tip-box">
            <strong>💡 Real-world use:</strong> Firewalls are your first line of defense. Always keep them enabled and maintain a blocklist of known malicious IPs.
        </div>

        <h3>🦠 Antivirus Scanner</h3>
        <h4>What it does:</h4>
        <p>Scans your system for malware, viruses, trojans, and other malicious software using signature-based and heuristic detection.</p>
        
        <h4>How to use:</h4>
        <ol>
            <li>Select "Antivirus Scan" from the tools</li>
            <li>Choose between "Full Scan" (comprehensive but slower) or "Quick Scan" (faster but less thorough)</li>
            <li>If threats are found, click "Quarantine All" to isolate them</li>
        </ol>

        <h4>Understanding results:</h4>
        <ul>
            <li><strong>Threats found:</strong> Number of malicious files detected</li>
            <li><strong>Quarantine:</strong> Isolates threats so they can't harm your system</li>
            <li>Regular scans help maintain system health</li>
        </ul>

        <h3>🎣 Phishing Email Detector</h3>
        <h4>What it does:</h4>
        <p>Analyzes emails to identify phishing attempts that try to steal credentials or install malware.</p>
        
        <h4>How to use:</h4>
        <ol>
            <li>Enter the email subject, sender address, and content</li>
            <li>Click "Analyze Email"</li>
            <li>Review the threat level and warnings</li>
            <li>If high risk, click "Block & Report"</li>
        </ol>

        <h4>Red flags to watch for:</h4>
        <ul>
            <li>Urgent language or threats ("Account suspended!")</li>
            <li>Requests to verify account information</li>
            <li>Suspicious sender domains</li>
            <li>Generic greetings ("Dear Customer")</li>
            <li>Links to unfamiliar websites</li>
        </ul>

        <div class="danger-box">
            <strong>⚠️ Warning:</strong> Phishing is one of the most common attack vectors. Always verify sender authenticity before clicking links or providing information.
        </div>

        <h3>🚨 Intrusion Detection System (IDS)</h3>
        <h4>What it does:</h4>
        <p>Monitors network traffic in real-time to detect suspicious activities, unauthorized access attempts, and anomalies.</p>
        
        <h4>How to use:</h4>
        <ol>
            <li>Click "Start Monitoring" to begin traffic analysis</li>
            <li>Watch for alerts in the activity log</li>
            <li>Review packet counts and alert numbers</li>
            <li>Click "Stop Monitoring" when done</li>
        </ol>

        <h4>What IDS detects:</h4>
        <ul>
            <li>Port scanning attempts</li>
            <li>Unusual traffic patterns</li>
            <li>Brute force login attempts</li>
            <li>Known attack signatures</li>
        </ul>

        <h3>🔐 Data Encryption</h3>
        <h4>What it does:</h4>
        <p>Protects sensitive data by converting it into unreadable ciphertext that can only be decrypted with the correct key.</p>
        
        <h4>How to use:</h4>
        <ol>
            <li>Enter the data you want to protect</li>
            <li>Choose an encryption method (AES-256, RSA-2048, or Base64)</li>
            <li>Click "Encrypt" to secure your data</li>
            <li>Click "Decrypt" to restore the original data</li>
        </ol>

        <h4>Encryption standards:</h4>
        <ul>
            <li><strong>AES-256:</strong> Military-grade symmetric encryption</li>
            <li><strong>RSA-2048:</strong> Asymmetric encryption for secure key exchange</li>
            <li><strong>Base64:</strong> Encoding method (not true encryption, for demo only)</li>
        </ul>

        <div class="success-box">
            <strong>✅ Best Practice:</strong> Always encrypt sensitive data at rest and in transit. Use strong encryption standards like AES-256.
        </div>

        <h3>🔒 VPN Configuration</h3>
        <h4>What it does:</h4>
        <p>Creates a secure, encrypted tunnel between your device and a remote server, protecting your internet traffic from eavesdropping.</p>
        
        <h4>How to use:</h4>
        <ol>
            <li>Select VPN server and protocol</li>
            <li>Choose encryption method</li>
            <li>Click "Connect VPN" to establish secure connection</li>
            <li>Monitor encrypted data flow</li>
        </ol>

        <h3>📊 SIEM Dashboard</h3>
        <h4>What it does:</h4>
        <p>Centralized security monitoring that aggregates and analyzes security events from across your infrastructure.</p>
        
        <h4>How to use:</h4>
        <ol>
            <li>Start monitoring to begin collecting security events</li>
            <li>Review real-time alerts and threat levels</li>
            <li>Generate comprehensive security reports</li>
        </ol>

        <h3>🍯 Honeypot Deployment</h3>
        <h4>What it does:</h4>
        <p>Deploys deceptive systems that appear vulnerable to attract and study attackers.</p>
        
        <h4>How to use:</h4>
        <ol>
            <li>Choose honeypot interaction level</li>
            <li>Select services to emulate</li>
            <li>Deploy and monitor for attacker activity</li>
            <li>Analyze captured attack data</li>
        </ol>
    `,
    
    attack: `
        <h3>⚔️ Attack Mode Tools</h3>
        <p>Learn offensive security techniques to identify and understand vulnerabilities. Use this knowledge responsibly and only in authorized environments.</p>

        <div class="danger-box">
            <strong>🚨 CRITICAL WARNING:</strong> These techniques should ONLY be used in controlled environments, on systems you own, or with explicit written permission. Unauthorized access is illegal!
        </div>

        <h3>💉 SQL Injection</h3>
        <h4>What it is:</h4>
        <p>SQL injection exploits vulnerabilities in database queries, allowing attackers to manipulate or extract database data.</p>
        
        <h4>How to test:</h4>
        <ol>
            <li>Enter username and password in the login form</li>
            <li>Try common SQL injection payloads (shown on screen)</li>
            <li>Examples: <code>' OR '1'='1</code>, <code>admin'--</code></li>
            <li>Observe if authentication is bypassed</li>
        </ol>

        <h4>Common injection patterns:</h4>
        <ul>
            <li><code>' OR '1'='1</code> - Always true condition</li>
            <li><code>admin'--</code> - Comments out password check</li>
            <li><code>'; DROP TABLE users--</code> - Database destruction</li>
        </ul>

        <h4>How to prevent:</h4>
        <ul>
            <li>Use parameterized queries (prepared statements)</li>
            <li>Input validation and sanitization</li>
            <li>Principle of least privilege for database accounts</li>
            <li>Web Application Firewalls (WAF)</li>
        </ul>

        <h3>⚡ Cross-Site Scripting (XSS)</h3>
        <h4>What it is:</h4>
        <p>XSS allows attackers to inject malicious scripts into web pages viewed by other users, potentially stealing cookies, session tokens, or personal data.</p>
        
        <h4>How to test:</h4>
        <ol>
            <li>Enter text in the comment input field</li>
            <li>Try XSS payloads like: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
            <li>Check if the script would execute</li>
        </ol>

        <h4>Types of XSS:</h4>
        <ul>
            <li><strong>Stored XSS:</strong> Malicious script stored in database</li>
            <li><strong>Reflected XSS:</strong> Script in URL parameters</li>
            <li><strong>DOM-based XSS:</strong> Client-side script manipulation</li>
        </ul>

        <h4>Prevention methods:</h4>
        <ul>
            <li>Output encoding (escape HTML, JavaScript, URLs)</li>
            <li>Content Security Policy (CSP) headers</li>
            <li>Input validation and sanitization</li>
            <li>HTTPOnly and Secure cookie flags</li>
        </ul>

        <h3>🔍 Port Scanner</h3>
        <h4>What it does:</h4>
        <p>Identifies open ports on a target system, revealing what services are running and potentially vulnerable.</p>
        
        <h4>How to use:</h4>
        <ol>
            <li>Enter the target IP address</li>
            <li>Click "Scan Ports"</li>
            <li>Review which ports are open and their associated services</li>
        </ol>

        <h4>Common ports and services:</h4>
        <ul>
            <li><strong>21 (FTP):</strong> File transfer - often vulnerable</li>
            <li><strong>22 (SSH):</strong> Secure shell - target for brute force</li>
            <li><strong>23 (Telnet):</strong> Unencrypted remote access - highly insecure</li>
            <li><strong>80 (HTTP):</strong> Web traffic - potential web vulnerabilities</li>
            <li><strong>443 (HTTPS):</strong> Encrypted web - SSL/TLS vulnerabilities</li>
            <li><strong>3306 (MySQL):</strong> Database - SQL injection risk</li>
            <li><strong>3389 (RDP):</strong> Remote desktop - brute force target</li>
        </ul>

        <div class="tip-box">
            <strong>💡 Defense Tip:</strong> Close unnecessary ports, use port knocking, and implement proper firewall rules to minimize attack surface.
        </div>

        <h3>🔓 Password Strength Testing</h3>
        <h4>What it does:</h4>
        <p>Tests password security by analyzing strength and attempting dictionary attacks.</p>
        
        <h4>How to use:</h4>
        <ol>
            <li>Enter a password to test</li>
            <li>Click "Analyze Strength" for detailed feedback</li>
            <li>Click "Attempt Dictionary Attack" to test crackability</li>
        </ol>

        <h4>Password strength factors:</h4>
        <ul>
            <li>Length (minimum 12 characters recommended)</li>
            <li>Character variety (uppercase, lowercase, numbers, symbols)</li>
            <li>Avoid common words and patterns</li>
            <li>Not found in breach databases</li>
        </ul>

        <h4>Attack methods:</h4>
        <ul>
            <li><strong>Dictionary Attack:</strong> Tests common passwords</li>
            <li><strong>Brute Force:</strong> Tries all possible combinations</li>
            <li><strong>Credential Stuffing:</strong> Uses leaked password databases</li>
            <li><strong>Rainbow Tables:</strong> Pre-computed hash lookups</li>
        </ul>

        <h3>💥 Denial of Service (DoS) Simulation</h3>
        <h4>What it is:</h4>
        <p>DoS attacks overwhelm a system with traffic or requests, making it unavailable to legitimate users.</p>
        
        <h4>How to simulate:</h4>
        <ol>
            <li>Enter target server address</li>
            <li>Set request rate (requests per second)</li>
            <li>Click "Start Attack" to begin simulation</li>
            <li>Watch server health degrade</li>
            <li>Click "Stop Attack" to halt</li>
        </ol>

        <h4>Types of DoS/DDoS:</h4>
        <ul>
            <li><strong>Volume-based:</strong> Floods bandwidth (UDP flood, ICMP flood)</li>
            <li><strong>Protocol-based:</strong> Exploits protocol weaknesses (SYN flood)</li>
            <li><strong>Application-layer:</strong> Targets web applications (HTTP flood)</li>
        </ul>

        <h4>Defense strategies:</h4>
        <ul>
            <li>Rate limiting and traffic filtering</li>
            <li>DDoS protection services (Cloudflare, AWS Shield)</li>
            <li>Load balancing and redundancy</li>
            <li>Anomaly detection and traffic analysis</li>
        </ul>

        <h3>🎯 Zero-Day Exploit</h3>
        <h4>What it is:</h4>
        <p>Exploits previously unknown vulnerabilities that have no available patches.</p>
        
        <h4>How to simulate:</h4>
        <ol>
            <li>Select target software and exploit type</li>
            <li>Launch the exploit attempt</li>
            <li>Observe if security controls prevent the attack</li>
        </ol>

        <h3>📡 Wireless Network Attack</h3>
        <h4>What it is:</h4>
        <p>Compromises wireless networks through various attack vectors.</p>
        
        <h4>How to simulate:</h4>
        <ol>
            <li>Select target network and attack method</li>
            <li>Execute the wireless attack</li>
            <li>Analyze success rate and captured data</li>
        </ol>

        <div class="warning-box">
            <strong>⚠️ Legal Notice:</strong> DoS attacks are illegal. This is a simulation for educational purposes only. Real attacks can result in criminal charges.
        </div>
    `,
    
    terminal: `
        <h3>💻 Terminal Commands</h3>
        <p>The terminal provides command-line access to system functions and security tools.</p>

        <h3>Available Commands</h3>

        <h4><code>help</code></h4>
        <p>Displays all available commands and their descriptions.</p>
        <pre>user@cyberSec:~$ help</pre>

        <h4><code>status</code></h4>
        <p>Shows current system status including:</p>
        <ul>
            <li>System Health percentage</li>
            <li>Firewall status (Active/Inactive)</li>
            <li>Antivirus status</li>
            <li>Current score</li>
        </ul>
        <pre>user@cyberSec:~$ status</pre>

        <h4><code>scan</code></h4>
        <p>Performs a quick malware scan of the system. Faster than the full antivirus scan but less comprehensive.</p>
        <pre>user@cyberSec:~$ scan</pre>
        <div class="tip-box">
            <strong>💡 Tip:</strong> Use quick scans for routine checks and full scans when you suspect infection.
        </div>

        <h4><code>firewall on/off</code></h4>
        <p>Enables or disables the system firewall.</p>
        <pre>user@cyberSec:~$ firewall on
user@cyberSec:~$ firewall off</pre>
        <div class="danger-box">
            <strong>⚠️ Warning:</strong> Disabling the firewall exposes your system to attacks and decreases your score!
        </div>

        <h4><code>ping [host]</code></h4>
        <p>Tests network connectivity to a specific host or IP address.</p>
        <pre>user@cyberSec:~$ ping google.com
user@cyberSec:~$ ping 192.168.1.1</pre>
        <p>Useful for diagnosing network issues and testing if systems are reachable.</p>

        <h4><code>whoami</code></h4>
        <p>Displays the current user account name.</p>
        <pre>user@cyberSec:~$ whoami</pre>

        <h4><code>clear</code></h4>
        <p>Clears the terminal screen of all previous commands and output.</p>
        <pre>user@cyberSec:~$ clear</pre>

        <h3>Terminal Tips & Tricks</h3>

        <h4>Command History</h4>
        <p>Press the UP arrow key to cycle through previously entered commands (feature coming soon!).</p>

        <h4>Tab Completion</h4>
        <p>Type partial commands and press TAB to auto-complete (feature coming soon!).</p>

        <h4>Chaining Commands</h4>
        <p>Execute multiple commands in sequence for automated workflows:</p>
        <ol>
            <li>Run <code>firewall on</code> to enable protection</li>
            <li>Run <code>scan</code> to check for threats</li>
            <li>Run <code>status</code> to verify system state</li>
        </ol>

        <h3>Understanding Terminal Output</h3>

        <h4>Color Coding</h4>
        <ul>
            <li><span style="color: #00ff88;">Green text:</span> Successful operations, normal output</li>
            <li><span style="color: #ffaa00;">Yellow text:</span> Warnings or important notices</li>
            <li><span style="color: #ff4444;">Red text:</span> Errors or critical issues</li>
        </ul>

        <h4>Common Usage Patterns</h4>
        <p><strong>System Health Check Routine:</strong></p>
        <pre>1. status    # Check current state
2. scan      # Quick malware scan
3. status    # Verify improvements</pre>

        <p><strong>Security Hardening:</strong></p>
        <pre>1. firewall on     # Enable network protection
2. scan            # Check for threats
3. status          # Confirm all security measures active</pre>

        <p><strong>Incident Response:</strong></p>
        <pre>1. firewall on     # Activate defenses
2. status          # Assess damage
3. scan            # Identify threats</pre>

        <div class="success-box">
            <strong>✅ Pro Tip:</strong> The terminal is fastest for quick operations. Use it alongside GUI tools for maximum efficiency!
        </div>

        <h3>Advanced Terminal Usage</h3>

        <h4>Monitoring and Logging</h4>
        <p>All terminal commands are logged in the Activity Log. Use this to:</p>
        <ul>
            <li>Track your actions during security incidents</li>
            <li>Review command history</li>
            <li>Analyze system events chronologically</li>
            <li>Generate security reports</li>
        </ul>

        <h4>Scripting Workflows</h4>
        <p>Create your own security workflows by combining commands:</p>
        <ul>
            <li><strong>Morning Security Check:</strong> status → scan → firewall on</li>
            <li><strong>Incident Response:</strong> firewall on → scan → status</li>
            <li><strong>Quick Audit:</strong> status → ping [gateway] → scan</li>
        </ul>

        <div class="tip-box">
            <strong>💡 Future Enhancement:</strong> Script support will allow you to save and automate command sequences!
        </div>

        <h3>Troubleshooting</h3>

        <h4>Command Not Found</h4>
        <p>If you see "Command not found", check for typos or type <code>help</code> to see available commands.</p>

        <h4>Unexpected Results</h4>
        <p>Check the Activity Log for detailed error messages and system events.</p>

        <h4>Terminal Not Responding</h4>
        <p>Refresh the page if the terminal becomes unresponsive. Your score and system health are tracked in memory.</p>
    `
};

// Initialize Application
document.addEventListener('DOMContentLoaded', () => {
    initializeUI();
    loadTools();
    setupEventListeners();
    setupTutorial();
    addLog('System initialized successfully', 'success');
});

// Initialize UI
function initializeUI() {
    updateSystemHealth();
    updateScore();
}

// Load Tools Based on Mode
function loadTools() {
    const toolsList = document.getElementById('toolsList');
    const currentTools = tools[state.mode];
    
    toolsList.innerHTML = '';
    
    // Add search box
    const searchBox = document.createElement('div');
    searchBox.className = 'tools-search';
    searchBox.innerHTML = `
        <input type="text" class="search-box" placeholder="🔍 Search tools..." id="toolsSearch">
    `;
    toolsList.appendChild(searchBox);
    
    // Add quick actions
    const quickActionsContainer = document.createElement('div');
    quickActionsContainer.className = 'quick-actions';
    quickActions[state.mode].forEach(action => {
        const actionBtn = document.createElement('div');
        actionBtn.className = 'quick-action';
        actionBtn.innerHTML = `
            <div style="font-size: 1rem; margin-bottom: 0.25rem;">${action.icon}</div>
            <div>${action.name}</div>
        `;
        actionBtn.onclick = () => executeQuickAction(action.action);
        quickActionsContainer.appendChild(actionBtn);
    });
    toolsList.appendChild(quickActionsContainer);
    
    // Add tools by category
    Object.keys(currentTools).forEach(category => {
        const categorySection = document.createElement('div');
        categorySection.className = 'tools-category';
        
        const categoryHeader = document.createElement('div');
        categoryHeader.className = 'category-header';
        categoryHeader.innerHTML = `
            <span class="category-icon">${getCategoryIcon(category)}</span>
            ${category}
        `;
        categorySection.appendChild(categoryHeader);
        
        const toolsGrid = document.createElement('div');
        toolsGrid.className = 'tools-grid';
        
        currentTools[category].forEach(tool => {
            const toolCard = document.createElement('div');
            toolCard.className = `tool-card ${state.mode}`;
            toolCard.innerHTML = `
                <span class="tool-icon">${tool.icon}</span>
                <div class="tool-name">${tool.name}</div>
                <div class="tool-desc">${tool.desc}</div>
                <div class="tool-status">
                    <span class="status-dot"></span>
                    <span>Ready</span>
                </div>
            `;
            toolCard.onclick = () => executeTool(tool.id);
            toolsGrid.appendChild(toolCard);
        });
        
        categorySection.appendChild(toolsGrid);
        toolsList.appendChild(categorySection);
    });
    
    // Add search functionality
    const searchInput = document.getElementById('toolsSearch');
    searchInput.addEventListener('input', filterTools);
}

// Quick action handlers
function executeQuickAction(action) {
    switch(action) {
        case 'runQuickScan':
            addLog('Quick scan initiated', 'info');
            showNotification('Quick Scan', 'Running quick system scan...', 'info');
            updateScore(5);
            break;
        case 'enableFirewall':
            if (!state.isFirewallActive) {
                state.isFirewallActive = true;
                addLog('Firewall enabled via quick action', 'success');
                showNotification('Firewall', 'Firewall enabled successfully', 'success');
                updateScore(10);
            }
            break;
        case 'checkStatus':
            addLog('System status checked', 'info');
            showNotification('Status', `Health: ${state.systemHealth}% | Score: ${state.score}`, 'info');
            break;
        case 'quickPortScan':
            addLog('Quick port scan initiated', 'info');
            showNotification('Port Scan', 'Scanning common ports...', 'info');
            updateScore(8);
            break;
        case 'testPassword':
            addLog('Password strength test initiated', 'info');
            showNotification('Password Test', 'Testing password security...', 'info');
            updateScore(8);
            break;
        case 'testSQL':
            addLog('SQL injection test initiated', 'info');
            showNotification('SQL Test', 'Testing for SQL vulnerabilities...', 'info');
            updateScore(8);
            break;
    }
}

// Filter tools based on search
function filterTools() {
    const searchTerm = document.getElementById('toolsSearch').value.toLowerCase();
    const toolCards = document.querySelectorAll('.tool-card');
    
    toolCards.forEach(card => {
        const toolName = card.querySelector('.tool-name').textContent.toLowerCase();
        const toolDesc = card.querySelector('.tool-desc').textContent.toLowerCase();
        
        if (toolName.includes(searchTerm) || toolDesc.includes(searchTerm)) {
            card.style.display = 'block';
        } else {
            card.style.display = 'none';
        }
    });
}

// Get category icons
function getCategoryIcon(category) {
    const icons = {
        'Network Security': '🌐',
        'Endpoint Protection': '💻',
        'Threat Detection': '🔍',
        'Data Protection': '🔒',
        'Web Application': '⚡',
        'Network Attacks': '📡',
        'System Exploitation': '🎯',
        'Social Engineering': '🎭'
    };
    return icons[category] || '🛠️';
}

// Setup Event Listeners
function setupEventListeners() {
    // Replace mode selector with compact version
    const modeSelector = document.querySelector('.mode-selector');
    if (modeSelector) {
        modeSelector.innerHTML = `
            <div class="mode-selector-compact">
                <div class="mode-tab active" data-mode="defense">
                    🛡️ Defense
                </div>
                <div class="mode-tab" data-mode="attack">
                    ⚔️ Attack
                </div>
            </div>
        `;
    }
    
    // Mode selector
    document.querySelectorAll('.mode-tab').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelectorAll('.mode-tab').forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            state.mode = e.target.dataset.mode;
            loadTools();
            addLog(`Switched to ${state.mode} mode`, 'info');
        });
    });

    // Terminal input
    const terminalInput = document.getElementById('terminalInput');
    terminalInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            executeCommand(terminalInput.value);
            terminalInput.value = '';
        }
    });
}

// Execute Terminal Commands
function executeCommand(cmd) {
    const terminal = document.getElementById('terminal');
    const line = document.createElement('div');
    line.className = 'terminal-line';
    line.textContent = `user@cyberSec:~$ ${cmd}`;
    terminal.appendChild(line);

    const response = document.createElement('div');
    response.className = 'terminal-line';

    switch(cmd.toLowerCase().trim()) {
        case 'help':
            response.innerHTML = `Available commands:<br>
                help - Show this help message<br>
                status - Show system status<br>
                scan - Quick malware scan<br>
                firewall on/off - Toggle firewall<br>
                clear - Clear terminal<br>
                ping [host] - Ping a host<br>
                whoami - Display current user`;
            break;
        case 'status':
            response.innerHTML = `System Health: ${state.systemHealth}%<br>
                Firewall: ${state.isFirewallActive ? 'Active' : 'Inactive'}<br>
                Antivirus: ${state.isAntivirusActive ? 'Active' : 'Inactive'}<br>
                Score: ${state.score}`;
            break;
        case 'scan':
            response.textContent = 'Scanning... No threats detected.';
            updateScore(10);
            break;
        case 'firewall on':
            state.isFirewallActive = true;
            response.textContent = 'Firewall activated successfully.';
            addLog('Firewall activated', 'success');
            break;
        case 'firewall off':
            state.isFirewallActive = false;
            response.textContent = 'Firewall deactivated.';
            addLog('Firewall deactivated', 'warning');
            break;
        case 'clear':
            terminal.innerHTML = '';
            return;
        case 'whoami':
            response.textContent = 'user';
            break;
        default:
            if (cmd.startsWith('ping ')) {
                const host = cmd.split(' ')[1];
                response.textContent = `PING ${host} (127.0.0.1): 56 data bytes\n64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.123 ms`;
            } else {
                response.textContent = `Command not found: ${cmd}. Type 'help' for available commands.`;
            }
    }

    terminal.appendChild(response);
    terminal.scrollTop = terminal.scrollHeight;
}

// Execute Tool
function executeTool(toolId) {
    addLog(`Executing tool: ${toolId}`, 'info');
    
    const browserContent = document.getElementById('browserContent');
    
    switch(toolId) {
        case 'firewall':
            renderFirewall(browserContent);
            break;
        case 'antivirus':
            renderAntivirus(browserContent);
            break;
        case 'phishing':
            renderPhishingDetector(browserContent);
            break;
        case 'ids':
            renderIDS(browserContent);
            break;
        case 'encryption':
            renderEncryption(browserContent);
            break;
        case 'sql-injection':
            renderSQLInjection(browserContent);
            break;
        case 'xss':
            renderXSS(browserContent);
            break;
        case 'port-scan':
            renderPortScan(browserContent);
            break;
        case 'password-crack':
            renderPasswordCracker(browserContent);
            break;
        case 'dos':
            renderDoS(browserContent);
            break;
        case 'backup':
            renderBackup(browserContent);
            break;
        case 'patch':
            renderPatchManagement(browserContent);
            break;
        case 'access-control':
            renderAccessControl(browserContent);
            break;
        case 'mitm':
            renderMITM(browserContent);
            break;
        case 'ransomware':
            renderRansomware(browserContent);
            break;
        case 'social-eng':
            renderSocialEngineering(browserContent);
            break;
        case 'vpn':
            renderVPN(browserContent);
            break;
        case 'siem':
            renderSIEM(browserContent);
            break;
        case 'honeypot':
            renderHoneypot(browserContent);
            break;
        case 'web-filter':
            renderWebFilter(browserContent);
            break;
        case 'zero-day':
            renderZeroDay(browserContent);
            break;
        case 'wireless-attack':
            renderWirelessAttack(browserContent);
            break;
    }
}

// Render Firewall Tool
function renderFirewall(container) {
    container.innerHTML = `
        <h2>🔥 Firewall Configuration</h2>
        <p>Configure firewall rules to protect your network</p>
        <div class="sim-form">
            <div class="form-group">
                <label>Block IP Address:</label>
                <input type="text" id="blockIP" placeholder="e.g., 192.168.1.100">
            </div>
            <button class="btn" onclick="blockIP()">Block IP</button>
            <button class="btn" onclick="toggleFirewall()">
                ${state.isFirewallActive ? 'Disable' : 'Enable'} Firewall
            </button>
            <div class="result-box" style="margin-top: 1rem;">
                <strong>Status:</strong> ${state.isFirewallActive ? '✅ Active' : '❌ Inactive'}<br>
                <strong>Blocked IPs:</strong> ${state.blockedIPs.length > 0 ? state.blockedIPs.join(', ') : 'None'}
            </div>
        </div>
    `;
}

window.blockIP = function() {
    const ip = document.getElementById('blockIP').value;
    if (ip && /^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
        state.blockedIPs.push(ip);
        addLog(`Blocked IP: ${ip}`, 'success');
        showNotification('Success', `IP ${ip} has been blocked`, 'success');
        updateScore(15);
        renderFirewall(document.getElementById('browserContent'));
    } else {
        showNotification('Error', 'Invalid IP address format', 'error');
    }
};

window.toggleFirewall = function() {
    state.isFirewallActive = !state.isFirewallActive;
    addLog(`Firewall ${state.isFirewallActive ? 'enabled' : 'disabled'}`, 
           state.isFirewallActive ? 'success' : 'warning');
    updateScore(state.isFirewallActive ? 20 : -10);
    renderFirewall(document.getElementById('browserContent'));
};

// Render Antivirus Tool
function renderAntivirus(container) {
    container.innerHTML = `
        <h2>🦠 Antivirus Scanner</h2>
        <p>Scan your system for malware and threats</p>
        <div class="sim-form">
            <button class="btn" onclick="runAntivirusScan()">Start Full Scan</button>
            <button class="btn" onclick="runQuickScan()">Quick Scan</button>
            <div id="scanResults" class="result-box" style="display: none; margin-top: 1rem;"></div>
        </div>
    `;
}

window.runAntivirusScan = function() {
    const results = document.getElementById('scanResults');
    results.style.display = 'block';
    results.innerHTML = '<strong>Scanning...</strong>';
    
    setTimeout(() => {
        const threats = Math.floor(Math.random() * 5);
        if (threats > 0) {
            results.innerHTML = `
                <strong>⚠️ Scan Complete</strong><br>
                Found ${threats} potential threats<br>
                <button class="btn" onclick="quarantineThreats(${threats})">Quarantine All</button>
            `;
            results.className = 'result-box vulnerable';
            updateSystemHealth(-threats * 5);
        } else {
            results.innerHTML = '<strong>✅ Scan Complete</strong><br>No threats detected';
            results.className = 'result-box protected';
            updateScore(25);
        }
        addLog(`Antivirus scan completed. Threats found: ${threats}`, threats > 0 ? 'warning' : 'success');
    }, 2000);
};

window.runQuickScan = function() {
    const results = document.getElementById('scanResults');
    results.style.display = 'block';
    results.innerHTML = '<strong>Quick scanning...</strong>';
    
    setTimeout(() => {
        results.innerHTML = '<strong>✅ Quick Scan Complete</strong><br>System appears clean';
        results.className = 'result-box protected';
        updateScore(10);
        addLog('Quick scan completed successfully', 'success');
    }, 1000);
};

window.quarantineThreats = function(count) {
    showNotification('Success', `Quarantined ${count} threats`, 'success');
    updateScore(count * 10);
    updateSystemHealth(count * 5);
    addLog(`Quarantined ${count} threats`, 'success');
    runAntivirusScan();
};

// Render Phishing Detector
function renderPhishingDetector(container) {
    container.innerHTML = `
        <h2>🎣 Phishing Email Detector</h2>
        <p>Analyze emails for phishing attempts</p>
        <div class="sim-form">
            <div class="form-group">
                <label>Email Subject:</label>
                <input type="text" id="emailSubject" placeholder="Enter email subject">
            </div>
            <div class="form-group">
                <label>Sender Email:</label>
                <input type="text" id="senderEmail" placeholder="sender@example.com">
            </div>
            <div class="form-group">
                <label>Email Content:</label>
                <input type="text" id="emailContent" placeholder="Email message text">
            </div>
            <button class="btn" onclick="analyzePhishing()">Analyze Email</button>
            <div id="phishingResults" class="result-box" style="display: none; margin-top: 1rem;"></div>
        </div>
    `;
}

window.analyzePhishing = function() {
    const subject = document.getElementById('emailSubject').value.toLowerCase();
    const sender = document.getElementById('senderEmail').value.toLowerCase();
    const content = document.getElementById('emailContent').value.toLowerCase();
    const results = document.getElementById('phishingResults');
    
    results.style.display = 'block';
    
    const phishingKeywords = ['urgent', 'verify', 'suspended', 'click here', 'winner', 'prize', 'password', 'account'];
    const suspiciousDomains = ['suspicious.com', 'fake-bank.com', 'phishy.net'];
    
    let threatLevel = 0;
    let warnings = [];
    
    phishingKeywords.forEach(keyword => {
        if (subject.includes(keyword) || content.includes(keyword)) {
            threatLevel++;
            warnings.push(`Contains suspicious keyword: "${keyword}"`);
        }
    });
    
    suspiciousDomains.forEach(domain => {
        if (sender.includes(domain)) {
            threatLevel += 2;
            warnings.push(`Sender from suspicious domain: ${domain}`);
        }
    });
    
    if (!sender.includes('@') || sender.includes('..')) {
        threatLevel++;
        warnings.push('Invalid email format');
    }
    
    if (threatLevel >= 3) {
        results.className = 'result-box vulnerable';
        results.innerHTML = `
            <strong>🚨 HIGH RISK - Likely Phishing</strong><br>
            Threat Level: ${threatLevel}/10<br>
            <strong>Warnings:</strong><br>
            ${warnings.map(w => `• ${w}`).join('<br>')}
            <br><button class="btn" onclick="blockPhishing()" style="margin-top: 1rem;">Block & Report</button>
        `;
        updateSystemHealth(-10);
    } else if (threatLevel > 0) {
        results.className = 'result-box';
        results.innerHTML = `
            <strong>⚠️ MEDIUM RISK - Suspicious</strong><br>
            Threat Level: ${threatLevel}/10<br>
            ${warnings.length > 0 ? '<strong>Warnings:</strong><br>' + warnings.map(w => `• ${w}`).join('<br>') : ''}
        `;
    } else {
        results.className = 'result-box protected';
        results.innerHTML = '<strong>✅ LOW RISK - Appears Safe</strong><br>No phishing indicators detected';
        updateScore(15);
    }
    
    addLog(`Phishing analysis completed. Threat level: ${threatLevel}`, threatLevel >= 3 ? 'error' : 'info');
};

window.blockPhishing = function() {
    showNotification('Success', 'Phishing email blocked and reported', 'success');
    updateScore(30);
    updateSystemHealth(10);
    addLog('Phishing attempt blocked', 'success');
};

// Render IDS
function renderIDS(container) {
    container.innerHTML = `
        <h2>🚨 Intrusion Detection System</h2>
        <p>Monitor network traffic for suspicious activity</p>
        <div class="sim-form">
            <button class="btn" onclick="startIDS()">Start Monitoring</button>
            <button class="btn" onclick="stopIDS()">Stop Monitoring</button>
            <div id="idsResults" class="result-box" style="margin-top: 1rem;">
                <strong>Status:</strong> Idle<br>
                <strong>Traffic Monitored:</strong> 0 packets<br>
                <strong>Alerts:</strong> 0
            </div>
        </div>
    `;
}

let idsInterval;
window.startIDS = function() {
    let packets = 0;
    let alerts = 0;
    const results = document.getElementById('idsResults');
    
    idsInterval = setInterval(() => {
        packets += Math.floor(Math.random() * 50) + 10;
        
        if (Math.random() < 0.3) {
            alerts++;
            addLog(`IDS Alert: Suspicious activity detected from ${generateRandomIP()}`, 'warning');
            updateSystemHealth(-3);
        }
        
        results.innerHTML = `
            <strong>Status:</strong> 🟢 Active Monitoring<br>
            <strong>Traffic Monitored:</strong> ${packets} packets<br>
            <strong>Alerts:</strong> ${alerts}
        `;
        results.className = alerts > 5 ? 'result-box vulnerable' : 'result-box protected';
    }, 2000);
    
    showNotification('IDS Started', 'Monitoring network traffic', 'info');
    updateScore(5);
};

window.stopIDS = function() {
    clearInterval(idsInterval);
    const results = document.getElementById('idsResults');
    results.innerHTML = '<strong>Status:</strong> Stopped';
    showNotification('IDS Stopped', 'Monitoring halted', 'info');
};

// Render Encryption Tool
function renderEncryption(container) {
    container.innerHTML = `
        <h2>🔐 Data Encryption</h2>
        <p>Encrypt sensitive data using various algorithms</p>
        <div class="sim-form">
            <div class="form-group">
                <label>Data to Encrypt:</label>
                <input type="text" id="plaintext" placeholder="Enter sensitive data">
            </div>
            <div class="form-group">
                <label>Encryption Method:</label>
                <select id="encMethod" style="width: 100%; padding: 0.75rem; background: rgba(0,0,0,0.5); border: 1px solid rgba(0,255,136,0.3); color: #e0e0e0; border-radius: 3px;">
                    <option value="aes">AES-256</option>
                    <option value="rsa">RSA-2048</option>
                    <option value="base64">Base64 (Demo)</option>
                </select>
            </div>
            <button class="btn" onclick="encryptData()">Encrypt</button>
            <button class="btn" onclick="decryptData()">Decrypt</button>
            <div id="encryptResults" class="result-box" style="display: none; margin-top: 1rem;"></div>
        </div>
    `;
}

let encryptedData = '';
window.encryptData = function() {
    const plaintext = document.getElementById('plaintext').value;
    const method = document.getElementById('encMethod').value;
    const results = document.getElementById('encryptResults');
    
    if (!plaintext) {
        showNotification('Error', 'Please enter data to encrypt', 'error');
        return;
    }
    
    results.style.display = 'block';
    
    if (method === 'base64') {
        encryptedData = btoa(plaintext);
    } else {
        encryptedData = Array.from(plaintext).map(c => 
            c.charCodeAt(0).toString(16).padStart(2, '0')
        ).join('') + '_' + method;
    }
    
    results.className = 'result-box protected';
    results.innerHTML = `
        <strong>✅ Encryption Successful</strong><br>
        <strong>Method:</strong> ${method.toUpperCase()}<br>
        <strong>Encrypted Data:</strong><br>
        <code style="word-break: break-all; font-size: 0.8rem;">${encryptedData}</code>
    `;
    
    addLog(`Data encrypted using ${method.toUpperCase()}`, 'success');
    updateScore(20);
};

window.decryptData = function() {
    const results = document.getElementById('encryptResults');
    
    if (!encryptedData) {
        showNotification('Error', 'No encrypted data available', 'error');
        return;
    }
    
    results.style.display = 'block';
    
    let decrypted;
    if (encryptedData.includes('_base64')) {
        decrypted = atob(encryptedData.replace('_base64', ''));
    } else if (encryptedData.includes('_')) {
        const hex = encryptedData.split('_')[0];
        decrypted = hex.match(/.{2}/g).map(h => String.fromCharCode(parseInt(h, 16))).join('');
    } else {
        decrypted = atob(encryptedData);
    }
    
    results.className = 'result-box protected';
    results.innerHTML = `
        <strong>✅ Decryption Successful</strong><br>
        <strong>Decrypted Data:</strong> ${decrypted}
    `;
    
    addLog('Data decrypted successfully', 'success');
    updateScore(10);
};

// Render SQL Injection Tool
function renderSQLInjection(container) {
    container.innerHTML = `
        <h2>💉 SQL Injection Testing</h2>
        <p>Test web applications for SQL injection vulnerabilities</p>
        <div class="sim-form">
            <div class="form-group">
                <label>Username:</label>
                <input type="text" id="sqlUsername" placeholder="admin">
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input type="text" id="sqlPassword" placeholder="password">
            </div>
            <button class="btn" onclick="testSQLInjection()">Test Login</button>
            <div id="sqlResults" class="result-box" style="display: none; margin-top: 1rem;"></div>
            <div class="result-box" style="margin-top: 1rem;">
                <strong>Common SQL Injection Payloads:</strong><br>
                • ' OR '1'='1<br>
                • admin'--<br>
                • ' OR 1=1--<br>
                • '; DROP TABLE users--
            </div>
        </div>
    `;
}

window.testSQLInjection = function() {
    const username = document.getElementById('sqlUsername').value;
    const password = document.getElementById('sqlPassword').value;
    const results = document.getElementById('sqlResults');
    
    results.style.display = 'block';
    
    const sqlInjectionPatterns = ["'", "OR", "1=1", "--", "DROP", "SELECT", ";"];
    let isVulnerable = false;
    
    sqlInjectionPatterns.forEach(pattern => {
        if (username.toUpperCase().includes(pattern) || password.toUpperCase().includes(pattern)) {
            isVulnerable = true;
        }
    });
    
    if (isVulnerable) {
        results.className = 'result-box vulnerable';
        results.innerHTML = `
            <strong>🚨 VULNERABLE!</strong><br>
            SQL Injection detected! The application is vulnerable.<br>
            <strong>Attack successful:</strong> Bypassed authentication<br>
            <em>In production, this would grant unauthorized access!</em><br>
            <button class="btn" onclick="patchSQLVuln()" style="margin-top: 1rem;">Apply Security Patch</button>
        `;
        updateScore(25);
        addLog('SQL injection vulnerability detected', 'warning');
    } else {
        results.className = 'result-box protected';
        results.innerHTML = `
            <strong>✅ PROTECTED</strong><br>
            No SQL injection detected. Login failed normally.<br>
            The application appears to use parameterized queries.
        `;
        addLog('SQL injection test completed - no vulnerability', 'success');
    }
};

window.patchSQLVuln = function() {
    showNotification('Patch Applied', 'SQL injection vulnerability has been patched', 'success');
    updateScore(30);
    addLog('Applied SQL injection security patch', 'success');
};

// Render XSS Tool
function renderXSS(container) {
    container.innerHTML = `
        <h2>⚡ Cross-Site Scripting (XSS) Testing</h2>
        <p>Test for XSS vulnerabilities in web applications</p>
        <div class="sim-form">
            <div class="form-group">
                <label>Comment Input:</label>
                <input type="text" id="xssInput" placeholder="Enter comment">
            </div>
            <button class="btn" onclick="testXSS()">Submit Comment</button>
            <div id="xssResults" class="result-box" style="display: none; margin-top: 1rem;"></div>
            <div class="result-box" style="margin-top: 1rem;">
                <strong>Common XSS Payloads:</strong><br>
                • &lt;script&gt;alert('XSS')&lt;/script&gt;<br>
                • &lt;img src=x onerror=alert('XSS')&gt;<br>
                • &lt;svg onload=alert('XSS')&gt;
            </div>
        </div>
    `;
}

window.testXSS = function() {
    const input = document.getElementById('xssInput').value;
    const results = document.getElementById('xssResults');
    
    results.style.display = 'block';
    
    const xssPatterns = ["<script", "onerror", "onload", "javascript:", "<img", "<svg"];
    let isVulnerable = false;
    
    xssPatterns.forEach(pattern => {
        if (input.toLowerCase().includes(pattern)) {
            isVulnerable = true;
        }
    });
    
    if (isVulnerable) {
        results.className = 'result-box vulnerable';
        results.innerHTML = `
            <strong>🚨 XSS VULNERABILITY DETECTED!</strong><br>
            The application is vulnerable to XSS attacks.<br>
            <strong>Malicious payload detected:</strong> ${input.replace(/</g, '&lt;').replace(/>/g, '&gt;')}<br>
            <em>In production, this could execute malicious scripts!</em><br>
            <button class="btn" onclick="patchXSS()" style="margin-top: 1rem;">Apply Input Sanitization</button>
        `;
        updateScore(25);
        addLog('XSS vulnerability found', 'warning');
    } else {
        results.className = 'result-box protected';
        results.innerHTML = `
            <strong>✅ INPUT SANITIZED</strong><br>
            No XSS payload detected. Comment posted safely:<br>
            "${input}"
        `;
        updateScore(10);
        addLog('XSS test passed - input is safe', 'success');
    }
};

window.patchXSS = function() {
    showNotification('Patch Applied', 'XSS vulnerability patched with input sanitization', 'success');
    updateScore(30);
    addLog('Applied XSS security patch', 'success');
};

// Render Port Scanner
function renderPortScan(container) {
    container.innerHTML = `
        <h2>🔍 Port Scanner</h2>
        <p>Scan target systems for open ports</p>
        <div class="sim-form">
            <div class="form-group">
                <label>Target IP:</label>
                <input type="text" id="targetIP" placeholder="192.168.1.1" value="192.168.1.100">
            </div>
            <button class="btn" onclick="scanPorts()">Scan Ports</button>
            <div id="portResults" class="result-box" style="display: none; margin-top: 1rem;"></div>
        </div>
    `;
}

window.scanPorts = function() {
    const ip = document.getElementById('targetIP').value;
    const results = document.getElementById('portResults');
    
    results.style.display = 'block';
    results.innerHTML = '<strong>Scanning ports...</strong>';
    
    setTimeout(() => {
        const commonPorts = [
            { port: 21, service: 'FTP', status: Math.random() > 0.7 },
            { port: 22, service: 'SSH', status: Math.random() > 0.5 },
            { port: 23, service: 'Telnet', status: Math.random() > 0.8 },
            { port: 80, service: 'HTTP', status: Math.random() > 0.3 },
            { port: 443, service: 'HTTPS', status: Math.random() > 0.2 },
            { port: 3306, service: 'MySQL', status: Math.random() > 0.7 },
            { port: 3389, service: 'RDP', status: Math.random() > 0.6 },
            { port: 8080, service: 'HTTP-Alt', status: Math.random() > 0.8 }
        ];
        
        const openPorts = commonPorts.filter(p => p.status);
        
        results.className = openPorts.length > 3 ? 'result-box vulnerable' : 'result-box';
        results.innerHTML = `
            <strong>Scan Results for ${ip}</strong><br>
            <strong>Open Ports:</strong><br>
            ${openPorts.length > 0 ? 
                openPorts.map(p => `• Port ${p.port} (${p.service}) - OPEN`).join('<br>') :
                'No open ports detected'}
            <br><br>
            <strong>Closed Ports:</strong> ${commonPorts.length - openPorts.length}
        `;
        
        updateScore(20);
        addLog(`Port scan completed on ${ip}. Found ${openPorts.length} open ports`, 'info');
    }, 2500);
};

// Render Password Cracker
function renderPasswordCracker(container) {
    container.innerHTML = `
        <h2>🔓 Password Strength Tester</h2>
        <p>Test password strength and crack weak passwords</p>
        <div class="sim-form">
            <div class="form-group">
                <label>Password to Test:</label>
                <input type="password" id="testPassword" placeholder="Enter password">
            </div>
            <button class="btn" onclick="analyzePassword()">Analyze Strength</button>
            <button class="btn" onclick="attemptCrack()">Attempt Dictionary Attack</button>
            <div id="passwordResults" class="result-box" style="display: none; margin-top: 1rem;"></div>
        </div>
    `;
}

window.analyzePassword = function() {
    const password = document.getElementById('testPassword').value;
    const results = document.getElementById('passwordResults');
    
    if (!password) {
        showNotification('Error', 'Please enter a password', 'error');
        return;
    }
    
    results.style.display = 'block';
    
    let strength = 0;
    let feedback = [];
    
    if (password.length >= 8) strength++;
    else feedback.push('Too short (min 8 characters)');
    
    if (password.length >= 12) strength++;
    if (/[a-z]/.test(password)) strength++;
    else feedback.push('Add lowercase letters');
    
    if (/[A-Z]/.test(password)) strength++;
    else feedback.push('Add uppercase letters');
    
    if (/\d/.test(password)) strength++;
    else feedback.push('Add numbers');
    
    if (/[^a-zA-Z\d]/.test(password)) strength++;
    else feedback.push('Add special characters');
    
    const strengthText = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong', 'Very Strong'][Math.min(strength, 5)];
    const color = strength < 3 ? 'vulnerable' : strength < 5 ? '' : 'protected';
    
    results.className = `result-box ${color}`;
    results.innerHTML = `
        <strong>Password Strength: ${strengthText} (${strength}/6)</strong><br>
        ${feedback.length > 0 ? '<strong>Improvements:</strong><br>' + feedback.map(f => `• ${f}`).join('<br>') : '✅ Excellent password!'}
    `;
    
    updateScore(15);
    addLog(`Password analyzed - Strength: ${strengthText}`, 'info');
};

window.attemptCrack = function() {
    const password = document.getElementById('testPassword').value;
    const results = document.getElementById('passwordResults');
    
    results.style.display = 'block';
    results.innerHTML = '<strong>Running dictionary attack...</strong>';
    
    setTimeout(() => {
        const commonPasswords = ['password', '123456', 'admin', 'letmein', 'welcome'];
        const isCracked = commonPasswords.includes(password.toLowerCase()) || password.length < 6;
        
        if (isCracked) {
            results.className = 'result-box vulnerable';
            results.innerHTML = `
                <strong>🚨 PASSWORD CRACKED!</strong><br>
                Time taken: ${Math.random() * 5 + 1 | 0} seconds<br>
                This password is too weak and easily crackable!
            `;
            updateScore(20);
        } else {
            results.className = 'result-box protected';
            results.innerHTML = `
                <strong>✅ PASSWORD SECURE</strong><br>
                Dictionary attack failed after 10,000 attempts.<br>
                This password appears resistant to basic attacks.
            `;
            updateScore(30);
        }
        
        addLog('Dictionary attack simulation completed', 'info');
    }, 3000);
};

// Render DoS Simulation
function renderDoS(container) {
    container.innerHTML = `
        <h2>💥 DoS Attack Simulation</h2>
        <p>Simulate a Denial of Service attack on a target</p>
        <div class="sim-form">
            <div class="form-group">
                <label>Target Server:</label>
                <input type="text" id="dosTarget" placeholder="target-server.com" value="test-server.local">
            </div>
            <div class="form-group">
                <label>Request Rate (req/sec):</label>
                <input type="number" id="dosRate" value="1000" min="100" max="10000">
            </div>
            <button class="btn" onclick="startDoS()">Start Attack</button>
            <button class="btn" onclick="stopDoS()">Stop Attack</button>
            <div id="dosResults" class="result-box" style="margin-top: 1rem;">
                <strong>Status:</strong> Idle<br>
                <strong>Requests Sent:</strong> 0<br>
                <strong>Server Status:</strong> Online
            </div>
        </div>
    `;
}

let dosInterval;
let dosRequests = 0;
window.startDoS = function() {
    const target = document.getElementById('dosTarget').value;
    const rate = document.getElementById('dosRate').value;
    const results = document.getElementById('dosResults');
    
    dosRequests = 0;
    let serverHealth = 100;
    
    dosInterval = setInterval(() => {
        dosRequests += parseInt(rate);
        serverHealth -= Math.random() * 10;
        
        if (serverHealth <= 0) {
            results.className = 'result-box vulnerable';
            results.innerHTML = `
                <strong>Status:</strong> 🔴 Attack Successful<br>
                <strong>Requests Sent:</strong> ${dosRequests.toLocaleString()}<br>
                <strong>Server Status:</strong> 💥 OFFLINE - Server Overwhelmed!
            `;
            clearInterval(dosInterval);
            updateScore(30);
            addLog(`DoS attack successful on ${target}`, 'warning');
            showNotification('Attack Complete', 'Target server is down', 'warning');
        } else {
            results.innerHTML = `
                <strong>Status:</strong> 🟡 Attack in Progress<br>
                <strong>Requests Sent:</strong> ${dosRequests.toLocaleString()}<br>
                <strong>Server Status:</strong> Degraded (${serverHealth.toFixed(0)}%)
            `;
        }
    }, 1000);
    
    addLog(`Started DoS attack on ${target} at ${rate} req/sec`, 'info');
};

window.stopDoS = function() {
    clearInterval(dosInterval);
    showNotification('Attack Stopped', 'DoS attack halted', 'info');
    addLog('DoS attack stopped', 'info');
};

// Render Backup System
function renderBackup(container) {
    container.innerHTML = `
        <h2>💾 Backup System</h2>
        <p>Create and manage system backups for disaster recovery</p>
        <div class="sim-form">
            <div class="form-group">
                <label>Backup Location:</label>
                <select id="backupLocation" style="width: 100%; padding: 0.75rem; background: rgba(0,0,0,0.5); border: 1px solid rgba(0,255,136,0.3); color: #e0e0e0; border-radius: 3px;">
                    <option value="local">Local Drive</option>
                    <option value="cloud">Cloud Storage</option>
                    <option value="external">External Device</option>
                </select>
            </div>
            <div class="form-group">
                <label>Backup Type:</label>
                <select id="backupType" style="width: 100%; padding: 0.75rem; background: rgba(0,0,0,0.5); border: 1px solid rgba(0,255,136,0.3); color: #e0e0e0; border-radius: 3px;">
                    <option value="full">Full Backup</option>
                    <option value="incremental">Incremental Backup</option>
                    <option value="differential">Differential Backup</option>
                </select>
            </div>
            <button class="btn" onclick="createBackup()">Create Backup</button>
            <button class="btn" onclick="restoreBackup()">Restore from Backup</button>
            <div id="backupResults" class="result-box" style="display: none; margin-top: 1rem;"></div>
        </div>
    `;
}

window.createBackup = function() {
    const location = document.getElementById('backupLocation').value;
    const type = document.getElementById('backupType').value;
    const results = document.getElementById('backupResults');
    
    results.style.display = 'block';
    results.innerHTML = '<strong>Creating backup...</strong>';
    
    setTimeout(() => {
        const size = Math.floor(Math.random() * 500) + 100;
        results.className = 'result-box protected';
        results.innerHTML = `
            <strong>✅ Backup Created Successfully</strong><br>
            <strong>Type:</strong> ${type.charAt(0).toUpperCase() + type.slice(1)}<br>
            <strong>Location:</strong> ${location.charAt(0).toUpperCase() + location.slice(1)}<br>
            <strong>Size:</strong> ${size} MB<br>
            <strong>Files:</strong> ${Math.floor(Math.random() * 10000) + 1000}<br>
            <strong>Time:</strong> ${new Date().toLocaleString()}
        `;
        updateScore(30);
        updateSystemHealth(5);
        addLog(`Backup created: ${type} to ${location}`, 'success');
        showNotification('Backup Complete', 'Your data is now protected', 'success');
    }, 3000);
};

window.restoreBackup = function() {
    const results = document.getElementById('backupResults');
    results.style.display = 'block';
    results.innerHTML = '<strong>Restoring backup...</strong>';
    
    setTimeout(() => {
        results.className = 'result-box protected';
        results.innerHTML = `
            <strong>✅ Restore Complete</strong><br>
            System restored to previous state<br>
            All data recovered successfully
        `;
        updateScore(25);
        updateSystemHealth(10);
        addLog('System restored from backup', 'success');
        showNotification('Restore Complete', 'System recovered successfully', 'success');
    }, 2500);
};

// Render Patch Management
function renderPatchManagement(container) {
    container.innerHTML = `
        <h2>🔧 Patch Management</h2>
        <p>Keep your system secure by applying the latest security patches</p>
        <div class="sim-form">
            <button class="btn" onclick="scanPatches()">Scan for Updates</button>
            <button class="btn" onclick="installPatches()">Install All Patches</button>
            <div id="patchResults" class="result-box" style="margin-top: 1rem;">
                <strong>Status:</strong> Ready to scan<br>
                <strong>Last Update:</strong> Unknown
            </div>
        </div>
    `;
}

window.scanPatches = function() {
    const results = document.getElementById('patchResults');
    results.innerHTML = '<strong>Scanning for available patches...</strong>';
    
    setTimeout(() => {
        const criticalPatches = Math.floor(Math.random() * 5);
        const importantPatches = Math.floor(Math.random() * 8) + 2;
        const optionalPatches = Math.floor(Math.random() * 15);
        
        if (criticalPatches > 0) {
            results.className = 'result-box vulnerable';
        } else {
            results.className = 'result-box';
        }
        
        results.innerHTML = `
            <strong>Scan Complete</strong><br>
            <strong>Critical:</strong> ${criticalPatches} patches 🔴<br>
            <strong>Important:</strong> ${importantPatches} patches 🟡<br>
            <strong>Optional:</strong> ${optionalPatches} patches 🟢<br>
            <br>
            ${criticalPatches > 0 ? '<em>⚠️ Critical patches require immediate installation!</em>' : ''}
        `;
        
        updateScore(10);
        addLog(`Patch scan found ${criticalPatches + importantPatches + optionalPatches} updates`, criticalPatches > 0 ? 'warning' : 'info');
    }, 2000);
};

window.installPatches = function() {
    const results = document.getElementById('patchResults');
    results.innerHTML = '<strong>Installing patches...</strong>';
    
    setTimeout(() => {
        results.className = 'result-box protected';
        results.innerHTML = `
            <strong>✅ All Patches Installed</strong><br>
            System is now up to date<br>
            <strong>Vulnerabilities Fixed:</strong> ${Math.floor(Math.random() * 20) + 5}<br>
            <strong>Next Check:</strong> ${new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toLocaleDateString()}
        `;
        updateScore(40);
        updateSystemHealth(15);
        addLog('Security patches installed successfully', 'success');
        showNotification('Patches Installed', 'System security updated', 'success');
    }, 4000);
};

// Render Access Control
function renderAccessControl(container) {
    container.innerHTML = `
        <h2>🔑 Access Control Management</h2>
        <p>Manage user permissions and access levels</p>
        <div class="sim-form">
            <div class="form-group">
                <label>Username:</label>
                <input type="text" id="aclUsername" placeholder="Enter username">
            </div>
            <div class="form-group">
                <label>Permission Level:</label>
                <select id="aclPermission" style="width: 100%; padding: 0.75rem; background: rgba(0,0,0,0.5); border: 1px solid rgba(0,255,136,0.3); color: #e0e0e0; border-radius: 3px;">
                    <option value="read">Read Only</option>
                    <option value="write">Read & Write</option>
                    <option value="admin">Administrator</option>
                </select>
            </div>
            <button class="btn" onclick="setPermissions()">Set Permissions</button>
            <button class="btn" onclick="auditAccess()">Audit Access Logs</button>
            <div id="aclResults" class="result-box" style="display: none; margin-top: 1rem;"></div>
        </div>
    `;
}

window.setPermissions = function() {
    const username = document.getElementById('aclUsername').value;
    const permission = document.getElementById('aclPermission').value;
    const results = document.getElementById('aclResults');
    
    if (!username) {
        showNotification('Error', 'Please enter a username', 'error');
        return;
    }
    
    results.style.display = 'block';
    results.className = 'result-box protected';
    results.innerHTML = `
        <strong>✅ Permissions Updated</strong><br>
        <strong>User:</strong> ${username}<br>
        <strong>Access Level:</strong> ${permission.charAt(0).toUpperCase() + permission.slice(1)}<br>
        <strong>Applied:</strong> ${new Date().toLocaleString()}
    `;
    
    updateScore(20);
    addLog(`Set ${permission} permissions for ${username}`, 'success');
    showNotification('Success', 'User permissions updated', 'success');
};

window.auditAccess = function() {
    const results = document.getElementById('aclResults');
    results.style.display = 'block';
    results.innerHTML = '<strong>Auditing access logs...</strong>';
    
    setTimeout(() => {
        const suspiciousAttempts = Math.floor(Math.random() * 10);
        results.className = suspiciousAttempts > 5 ? 'result-box vulnerable' : 'result-box protected';
        results.innerHTML = `
            <strong>Audit Complete</strong><br>
            <strong>Total Login Attempts:</strong> ${Math.floor(Math.random() * 500) + 100}<br>
            <strong>Successful Logins:</strong> ${Math.floor(Math.random() * 450) + 50}<br>
            <strong>Failed Attempts:</strong> ${Math.floor(Math.random() * 50)}<br>
            <strong>Suspicious Activity:</strong> ${suspiciousAttempts} events ${suspiciousAttempts > 5 ? '⚠️' : '✅'}<br>
            ${suspiciousAttempts > 5 ? '<br><em>Review suspicious activities immediately!</em>' : ''}
        `;
        
        updateScore(15);
        addLog(`Access audit found ${suspiciousAttempts} suspicious events`, suspiciousAttempts > 5 ? 'warning' : 'success');
    }, 2000);
};

// Render Man-in-the-Middle Attack
function renderMITM(container) {
    container.innerHTML = `
        <h2>👤 Man-in-the-Middle Attack</h2>
        <p>Intercept and analyze network communications</p>
        <div class="sim-form">
            <div class="form-group">
                <label>Target Network:</label>
                <input type="text" id="mitmTarget" placeholder="192.168.1.0/24" value="192.168.1.0/24">
            </div>
            <button class="btn" onclick="startMITM()">Start Interception</button>
            <button class="btn" onclick="stopMITM()">Stop Attack</button>
            <div id="mitmResults" class="result-box" style="margin-top: 1rem;">
                <strong>Status:</strong> Idle<br>
                <strong>Packets Captured:</strong> 0<br>
                <strong>Credentials Found:</strong> 0
            </div>
        </div>
    `;
}

let mitmInterval;
window.startMITM = function() {
    const target = document.getElementById('mitmTarget').value;
    const results = document.getElementById('mitmResults');
    let packets = 0;
    let credentials = 0;
    
    mitmInterval = setInterval(() => {
        packets += Math.floor(Math.random() * 50) + 20;
        
        if (Math.random() < 0.2) {
            credentials++;
        }
        
        results.className = 'result-box vulnerable';
        results.innerHTML = `
            <strong>Status:</strong> 🔴 Active Interception<br>
            <strong>Target:</strong> ${target}<br>
            <strong>Packets Captured:</strong> ${packets}<br>
            <strong>Credentials Found:</strong> ${credentials}<br>
            <strong>Data Intercepted:</strong> ${(packets * 0.5).toFixed(1)} MB
        `;
    }, 1500);
    
    addLog(`Started MITM attack on ${target}`, 'warning');
    showNotification('MITM Active', 'Intercepting network traffic', 'warning');
    updateScore(25);
};

window.stopMITM = function() {
    clearInterval(mitmInterval);
    showNotification('MITM Stopped', 'Attack terminated', 'info');
    addLog('MITM attack stopped', 'info');
};

// Render Ransomware Simulation
function renderRansomware(container) {
    container.innerHTML = `
        <h2>🔒 Ransomware Simulation</h2>
        <p>Simulate a ransomware attack to test defenses</p>
        <div class="sim-form">
            <div class="form-group">
                <label>Attack Vector:</label>
                <select id="ransomVector" style="width: 100%; padding: 0.75rem; background: rgba(0,0,0,0.5); border: 1px solid rgba(0,255,136,0.3); color: #e0e0e0; border-radius: 3px;">
                    <option value="email">Phishing Email</option>
                    <option value="download">Malicious Download</option>
                    <option value="exploit">Software Exploit</option>
                </select>
            </div>
            <button class="btn" onclick="simulateRansomware()">Launch Simulation</button>
            <div id="ransomResults" class="result-box" style="display: none; margin-top: 1rem;"></div>
        </div>
    `;
}

window.simulateRansomware = function() {
    const vector = document.getElementById('ransomVector').value;
    const results = document.getElementById('ransomResults');
    
    results.style.display = 'block';
    results.innerHTML = '<strong>Simulating ransomware attack...</strong>';
    
    setTimeout(() => {
        const filesEncrypted = Math.floor(Math.random() * 5000) + 1000;
        const isBlocked = state.isFirewallActive && state.isAntivirusActive;
        
        if (isBlocked) {
            results.className = 'result-box protected';
            results.innerHTML = `
                <strong>✅ ATTACK BLOCKED!</strong><br>
                Your security measures prevented the ransomware.<br>
                <strong>Vector:</strong> ${vector}<br>
                <strong>Detection:</strong> ${state.isAntivirusActive ? 'Antivirus' : 'Firewall'}<br>
                <em>No files were encrypted. System is secure!</em>
            `;
            updateScore(50);
            updateSystemHealth(10);
        } else {
            results.className = 'result-box vulnerable';
            results.innerHTML = `
                <strong>🚨 RANSOMWARE ACTIVE!</strong><br>
                <strong>Files Encrypted:</strong> ${filesEncrypted}<br>
                <strong>Vector:</strong> ${vector}<br>
                <strong>Ransom Demand:</strong> 5 BTC<br>
                <em>⚠️ Enable firewall and antivirus to prevent this!</em>
            `;
            updateScore(30);
            updateSystemHealth(-30);
        }
        
        addLog(`Ransomware simulation via ${vector} - ${isBlocked ? 'Blocked' : 'Successful'}`, isBlocked ? 'success' : 'error');
    }, 3000);
};

// Render Social Engineering
function renderSocialEngineering(container) {
    container.innerHTML = `
        <h2>🎭 Social Engineering Simulation</h2>
        <p>Test human vulnerabilities through psychological manipulation</p>
        <div class="sim-form">
            <div class="form-group">
                <label>Attack Type:</label>
                <select id="socialType" style="width: 100%; padding: 0.75rem; background: rgba(0,0,0,0.5); border: 1px solid rgba(0,255,136,0.3); color: #e0e0e0; border-radius: 3px;">
                    <option value="pretexting">Pretexting</option>
                    <option value="baiting">Baiting</option>
                    <option value="tailgating">Tailgating</option>
                    <option value="quid-pro-quo">Quid Pro Quo</option>
                </select>
            </div>
            <div class="form-group">
                <label>Target Profile:</label>
                <input type="text" id="socialTarget" placeholder="e.g., IT Department">
            </div>
            <button class="btn" onclick="launchSocialEngineering()">Launch Attack</button>
            <div id="socialResults" class="result-box" style="display: none; margin-top: 1rem;"></div>
        </div>
    `;
}

window.launchSocialEngineering = function() {
    const type = document.getElementById('socialType').value;
    const target = document.getElementById('socialTarget').value || 'General Staff';
    const results = document.getElementById('socialResults');
    
    results.style.display = 'block';
    results.innerHTML = '<strong>Executing social engineering attack...</strong>';
    
    setTimeout(() => {
        const successRate = Math.floor(Math.random() * 100);
        const compromised = Math.floor(Math.random() * 20) + 1;
        
        results.className = successRate > 60 ? 'result-box vulnerable' : 'result-box';
        results.innerHTML = `
            <strong>${successRate > 60 ? '🚨 ATTACK SUCCESSFUL' : '⚠️ PARTIAL SUCCESS'}</strong><br>
            <strong>Type:</strong> ${type.charAt(0).toUpperCase() + type.slice(1)}<br>
            <strong>Target:</strong> ${target}<br>
            <strong>Success Rate:</strong> ${successRate}%<br>
            <strong>Users Compromised:</strong> ${compromised}<br>
            <strong>Credentials Obtained:</strong> ${Math.floor(compromised * 0.7)}<br>
            <br>
            <em>${successRate > 60 ? '⚠️ Security awareness training recommended!' : 'Some users fell for the attack. Improve training.'}</em>
        `;
        
        updateScore(35);
        if (successRate > 60) {
            updateSystemHealth(-15);
        }
        addLog(`Social engineering ${type} attack: ${successRate}% success rate`, successRate > 60 ? 'warning' : 'info');
    }, 2500);
};

// VPN Setup Tool
function renderVPN(container) {
    container.innerHTML = `
        <h2>🔒 VPN Configuration</h2>
        <p>Set up secure Virtual Private Network connections</p>
        <div class="sim-form">
            <div class="form-group">
                <label>VPN Server:</label>
                <input type="text" id="vpnServer" placeholder="vpn.securecompany.com">
            </div>
            <div class="form-group">
                <label>Protocol:</label>
                <select id="vpnProtocol">
                    <option value="openvpn">OpenVPN</option>
                    <option value="wireguard">WireGuard</option>
                    <option value="ikev2">IKEv2</option>
                </select>
            </div>
            <div class="form-group">
                <label>Encryption:</label>
                <select id="vpnEncryption">
                    <option value="aes-256">AES-256</option>
                    <option value="chaCha20">ChaCha20</option>
                    <option value="aes-128">AES-128</option>
                </select>
            </div>
            <button class="btn" onclick="setupVPN()">Connect VPN</button>
            <button class="btn" onclick="disconnectVPN()">Disconnect</button>
            <div id="vpnResults" class="result-box" style="margin-top: 1rem;">
                <strong>Status:</strong> Disconnected<br>
                <strong>Data Encrypted:</strong> 0 MB
            </div>
        </div>
    `;
}

window.setupVPN = function() {
    const server = document.getElementById('vpnServer').value || 'vpn.securecompany.com';
    const protocol = document.getElementById('vpnProtocol').value;
    const encryption = document.getElementById('vpnEncryption').value;
    const results = document.getElementById('vpnResults');
    
    results.className = 'result-box protected';
    results.innerHTML = `
        <strong>✅ VPN Connected</strong><br>
        <strong>Server:</strong> ${server}<br>
        <strong>Protocol:</strong> ${protocol}<br>
        <strong>Encryption:</strong> ${encryption}<br>
        <strong>Status:</strong> 🟢 Secure Connection<br>
        <strong>Data Encrypted:</strong> ${Math.floor(Math.random() * 1000)} MB
    `;
    
    updateScore(25);
    updateSystemHealth(10);
    addLog(`VPN connected using ${protocol} with ${encryption} encryption`, 'success');
    showNotification('VPN Active', 'Secure connection established', 'success');
};

window.disconnectVPN = function() {
    const results = document.getElementById('vpnResults');
    results.className = 'result-box';
    results.innerHTML = '<strong>Status:</strong> Disconnected<br><strong>Data Encrypted:</strong> 0 MB';
    addLog('VPN disconnected', 'info');
};

// SIEM Dashboard
function renderSIEM(container) {
    container.innerHTML = `
        <h2>📊 SIEM Dashboard</h2>
        <p>Security Information and Event Management - Centralized security monitoring</p>
        <div class="sim-form">
            <button class="btn" onclick="startSIEM()">Start Monitoring</button>
            <button class="btn" onclick="generateSIEMReport()">Generate Report</button>
            <div id="siemResults" class="result-box" style="margin-top: 1rem;">
                <strong>Status:</strong> Ready<br>
                <strong>Alerts:</strong> 0<br>
                <strong>Events Processed:</strong> 0
            </div>
            <div id="siemAlerts" style="margin-top: 1rem; max-height: 200px; overflow-y: auto;"></div>
        </div>
    `;
}

let siemInterval;
window.startSIEM = function() {
    const results = document.getElementById('siemResults');
    const alerts = document.getElementById('siemAlerts');
    let events = 0;
    let alertCount = 0;
    
    siemInterval = setInterval(() => {
        events += Math.floor(Math.random() * 100) + 50;
        
        if (Math.random() < 0.4) {
            alertCount++;
            const alertTypes = [
                'Multiple failed login attempts',
                'Unusual network traffic pattern',
                'Suspicious file access',
                'Privilege escalation attempt',
                'Malware signature detected',
                'Data exfiltration attempt'
            ];
            const alert = alertTypes[Math.floor(Math.random() * alertTypes.length)];
            
            const alertDiv = document.createElement('div');
            alertDiv.className = 'log-entry warning';
            alertDiv.textContent = `[${new Date().toLocaleTimeString()}] ${alert}`;
            alerts.appendChild(alertDiv);
            
            if (alertCount > 10) {
                alerts.removeChild(alerts.firstChild);
            }
        }
        
        results.innerHTML = `
            <strong>Status:</strong> 🟢 Active Monitoring<br>
            <strong>Alerts:</strong> ${alertCount}<br>
            <strong>Events Processed:</strong> ${events.toLocaleString()}<br>
            <strong>Threat Level:</strong> ${alertCount > 5 ? 'High' : alertCount > 2 ? 'Medium' : 'Low'}
        `;
        
        results.className = alertCount > 5 ? 'result-box vulnerable' : 'result-box protected';
    }, 2000);
    
    addLog('SIEM monitoring started', 'success');
    updateScore(15);
};

window.generateSIEMReport = function() {
    showNotification('Report Generated', 'SIEM security report created', 'success');
    updateScore(20);
    addLog('Generated comprehensive SIEM security report', 'success');
};

// Honeypot System
function renderHoneypot(container) {
    container.innerHTML = `
        <h2>🍯 Honeypot Deployment</h2>
        <p>Deploy deceptive systems to detect and analyze attackers</p>
        <div class="sim-form">
            <div class="form-group">
                <label>Honeypot Type:</label>
                <select id="honeypotType">
                    <option value="low">Low Interaction</option>
                    <option value="medium">Medium Interaction</option>
                    <option value="high">High Interaction</option>
                </select>
            </div>
            <div class="form-group">
                <label>Services to Emulate:</label>
                <div>
                    <input type="checkbox" id="service-ssh" checked> SSH<br>
                    <input type="checkbox" id="service-ftp" checked> FTP<br>
                    <input type="checkbox" id="service-http" checked> HTTP<br>
                    <input type="checkbox" id="service-database"> Database
                </div>
            </div>
            <button class="btn" onclick="deployHoneypot()">Deploy Honeypot</button>
            <button class="btn" onclick="analyzeHoneypot()">Analyze Attacks</button>
            <div id="honeypotResults" class="result-box" style="margin-top: 1rem;">
                <strong>Status:</strong> Not Deployed<br>
                <strong>Attackers Captured:</strong> 0
            </div>
        </div>
    `;
}

window.deployHoneypot = function() {
    const type = document.getElementById('honeypotType').value;
    const results = document.getElementById('honeypotResults');
    
    results.className = 'result-box protected';
    results.innerHTML = `
        <strong>✅ Honeypot Deployed</strong><br>
        <strong>Type:</strong> ${type} Interaction<br>
        <strong>Status:</strong> 🟢 Monitoring for attackers<br>
        <strong>Attackers Captured:</strong> 0<br>
        <em>Honeypot is actively collecting attack data...</em>
    `;
    
    // Simulate attackers over time
    setTimeout(() => {
        const attackers = Math.floor(Math.random() * 15) + 5;
        results.innerHTML = `
            <strong>✅ Honeypot Active</strong><br>
            <strong>Type:</strong> ${type} Interaction<br>
            <strong>Status:</strong> 🟢 ${attackers} attackers captured<br>
            <strong>Attackers Captured:</strong> ${attackers}<br>
            <strong>Data Collected:</strong> ${Math.floor(Math.random() * 500) + 100} MB
        `;
    }, 3000);
    
    updateScore(30);
    addLog(`Deployed ${type} interaction honeypot`, 'success');
};

window.analyzeHoneypot = function() {
    showNotification('Analysis Complete', 'Honeypot data analyzed - Attack patterns identified', 'success');
    updateScore(25);
    addLog('Analyzed honeypot attack data', 'info');
};

// Web Filter
function renderWebFilter(container) {
    container.innerHTML = `
        <h2>🌐 Web Content Filter</h2>
        <p>Block malicious and inappropriate websites</p>
        <div class="sim-form">
            <div class="form-group">
                <label>Website URL to Block:</label>
                <input type="text" id="blockUrl" placeholder="malicious-site.com">
            </div>
            <div class="form-group">
                <label>Category:</label>
                <select id="urlCategory">
                    <option value="malware">Malware Distribution</option>
                    <option value="phishing">Phishing</option>
                    <option value="pornography">Adult Content</option>
                    <option value="gambling">Gambling</option>
                    <option value="social">Social Media</option>
                </select>
            </div>
            <button class="btn" onclick="blockWebsite()">Block Website</button>
            <button class="btn" onclick="testWebFilter()">Test Filter</button>
            <div id="webFilterResults" class="result-box" style="margin-top: 1rem;">
                <strong>Status:</strong> Active<br>
                <strong>Websites Blocked:</strong> 0<br>
                <strong>Requests Blocked:</strong> 0
            </div>
        </div>
    `;
}

let blockedSites = [];
let blockedRequests = 0;

window.blockWebsite = function() {
    const url = document.getElementById('blockUrl').value;
    const category = document.getElementById('urlCategory').value;
    
    if (url && !blockedSites.includes(url)) {
        blockedSites.push(url);
        blockedRequests += Math.floor(Math.random() * 50) + 10;
        
        const results = document.getElementById('webFilterResults');
        results.innerHTML = `
            <strong>Status:</strong> Active<br>
            <strong>Websites Blocked:</strong> ${blockedSites.length}<br>
            <strong>Requests Blocked:</strong> ${blockedRequests}<br>
            <strong>Last Blocked:</strong> ${url} (${category})
        `;
        
        updateScore(15);
        addLog(`Blocked website: ${url} (${category})`, 'success');
        showNotification('Website Blocked', `${url} added to blocklist`, 'success');
    }
};

window.testWebFilter = function() {
    const testSites = [
        'malicious-download.com',
        'fake-bank-login.com',
        'adult-content.site',
        'gambling-casino.net'
    ];
    
    const testSite = testSites[Math.floor(Math.random() * testSites.length)];
    const isBlocked = Math.random() > 0.3;
    
    if (isBlocked) {
        showNotification('Access Blocked', `${testSite} was blocked by web filter`, 'success');
        updateScore(10);
    } else {
        showNotification('Access Allowed', `${testSite} passed through filter`, 'warning');
    }
};

// Zero-Day Exploit
function renderZeroDay(container) {
    container.innerHTML = `
        <h2>🎯 Zero-Day Exploit Simulation</h2>
        <p>Exploit previously unknown vulnerabilities</p>
        <div class="sim-form">
            <div class="form-group">
                <label>Target Software:</label>
                <select id="targetSoftware">
                    <option value="browser">Web Browser</option>
                    <option value="office">Office Suite</option>
                    <option value="os">Operating System</option>
                    <option value="media">Media Player</option>
                </select>
            </div>
            <div class="form-group">
                <label>Exploit Type:</label>
                <select id="exploitType">
                    <option value="memory">Memory Corruption</option>
                    <option value="logic">Logic Flaw</option>
                    <option value="config">Configuration Error</option>
                </select>
            </div>
            <button class="btn" onclick="launchZeroDay()">Launch Exploit</button>
            <div id="zeroDayResults" class="result-box" style="display: none; margin-top: 1rem;"></div>
        </div>
    `;
}

window.launchZeroDay = function() {
    const software = document.getElementById('targetSoftware').value;
    const exploitType = document.getElementById('exploitType').value;
    const results = document.getElementById('zeroDayResults');
    
    results.style.display = 'block';
    results.innerHTML = '<strong>Executing zero-day exploit...</strong>';
    
    setTimeout(() => {
        const success = Math.random() > 0.4;
        
        if (success) {
            results.className = 'result-box vulnerable';
            results.innerHTML = `
                <strong>🚨 EXPLOIT SUCCESSFUL!</strong><br>
                <strong>Target:</strong> ${software}<br>
                <strong>Method:</strong> ${exploitType}<br>
                <strong>Impact:</strong> Remote Code Execution<br>
                <strong>Detection:</strong> Not detected by antivirus<br>
                <em>This demonstrates why prompt patching is critical!</em>
            `;
            updateScore(40);
            updateSystemHealth(-25);
        } else {
            results.className = 'result-box protected';
            results.innerHTML = `
                <strong>✅ EXPLOIT FAILED</strong><br>
                <strong>Target:</strong> ${software}<br>
                <strong>Method:</strong> ${exploitType}<br>
                <strong>Reason:</strong> System protections prevented exploitation<br>
                <em>Modern security controls can prevent zero-day attacks</em>
            `;
            updateScore(20);
        }
        
        addLog(`Zero-day attack on ${software}: ${success ? 'Successful' : 'Failed'}`, success ? 'warning' : 'info');
    }, 3000);
};

// Wireless Attack
function renderWirelessAttack(container) {
    container.innerHTML = `
        <h2>📡 Wireless Network Attack</h2>
        <p>Compromise wireless networks and protocols</p>
        <div class="sim-form">
            <div class="form-group">
                <label>Target Network:</label>
                <input type="text" id="targetNetwork" placeholder="HomeWiFi" value="Corporate_WLAN">
            </div>
            <div class="form-group">
                <label>Attack Method:</label>
                <select id="wirelessAttack">
                    <option value="evil-twin">Evil Twin Attack</option>
                    <option value="deauth">Deauthentication Attack</option>
                    <option value="wps">WPS PIN Attack</option>
                    <option value="captive">Captive Portal Bypass</option>
                </select>
            </div>
            <button class="btn" onclick="startWirelessAttack()">Start Attack</button>
            <div id="wirelessResults" class="result-box" style="margin-top: 1rem;">
                <strong>Status:</strong> Ready<br>
                <strong>Networks Detected:</strong> 0
            </div>
        </div>
    `;
}

window.startWirelessAttack = function() {
    const network = document.getElementById('targetNetwork').value;
    const method = document.getElementById('wirelessAttack').value;
    const results = document.getElementById('wirelessResults');
    
    results.innerHTML = '<strong>Scanning for wireless networks...</strong>';
    
    setTimeout(() => {
        const networks = Math.floor(Math.random() * 15) + 5;
        results.innerHTML = `
            <strong>Wireless Networks Found:</strong> ${networks}<br>
            <strong>Target:</strong> ${network}<br>
            <strong>Method:</strong> ${method.replace('-', ' ')}<br>
            <strong>Status:</strong> Executing attack...
        `;
        
        setTimeout(() => {
            const success = Math.random() > 0.5;
            results.className = success ? 'result-box vulnerable' : 'result-box';
            results.innerHTML = `
                <strong>${success ? '🚨 ATTACK SUCCESSFUL' : '⚠️ ATTACK FAILED'}</strong><br>
                <strong>Target:</strong> ${network}<br>
                <strong>Method:</strong> ${method.replace('-', ' ')}<br>
                <strong>Result:</strong> ${success ? 'Network compromised' : 'Security measures prevented access'}<br>
                ${success ? '<em>Wireless credentials captured!</em>' : '<em>Enable WPA3 for better protection</em>'}
            `;
            
            updateScore(success ? 35 : 15);
            if (success) updateSystemHealth(-20);
            addLog(`Wireless ${method} attack: ${success ? 'Successful' : 'Failed'}`, success ? 'warning' : 'info');
        }, 2000);
    }, 2000);
};

// Tutorial System
function setupTutorial() {
    document.querySelectorAll('.tutorial-tab').forEach(tab => {
        tab.addEventListener('click', (e) => {
            document.querySelectorAll('.tutorial-tab').forEach(t => t.classList.remove('active'));
            e.target.classList.add('active');
            
            const section = e.target.dataset.section;
            loadTutorialSection(section);
        });
    });
}

function openTutorial() {
    const modal = document.getElementById('tutorialModal');
    modal.style.display = 'block';
    loadTutorialSection('overview');
    addLog('Opened tutorial guide', 'info');
}

function closeTutorial() {
    const modal = document.getElementById('tutorialModal');
    modal.style.display = 'none';
}

function loadTutorialSection(section) {
    const content = document.getElementById('tutorialContent');
    content.innerHTML = tutorialContent[section] || '<p>Content not found.</p>';
    content.scrollTop = 0;
}

window.onclick = function(event) {
    const modal = document.getElementById('tutorialModal');
    if (event.target === modal) {
        closeTutorial();
    }
}

window.openTutorial = openTutorial;
window.closeTutorial = closeTutorial;

// Utility Functions
function updateSystemHealth(change = 0) {
    state.systemHealth = Math.max(0, Math.min(100, state.systemHealth + change));
    document.getElementById('systemHealth').textContent = state.systemHealth + '%';
    
    const healthEl = document.getElementById('systemHealth');
    if (state.systemHealth < 30) {
        healthEl.style.color = '#ff4444';
    } else if (state.systemHealth < 70) {
        healthEl.style.color = '#ffaa00';
    } else {
        healthEl.style.color = '#00ff88';
    }
}

function updateScore(points = 0) {
    state.score += points;
    document.getElementById('score').textContent = state.score;
}

function addLog(message, type = 'info') {
    const log = document.getElementById('activityLog');
    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;
    const time = new Date().toLocaleTimeString();
    entry.textContent = `[${time}] ${message}`;
    log.insertBefore(entry, log.firstChild);
    
    while (log.children.length > 20) {
        log.removeChild(log.lastChild);
    }
}

function showNotification(title, message, type = 'info') {
    const notifArea = document.getElementById('notifications');
    const notif = document.createElement('div');
    notif.className = `notification ${type}`;
    notif.innerHTML = `
        <div class="notification-title">${title}</div>
        <div class="notification-message">${message}</div>
    `;
    notifArea.appendChild(notif);
    
    setTimeout(() => notif.remove(), 5000);
}

function generateRandomIP() {
    return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
}
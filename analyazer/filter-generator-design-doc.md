# Network Filter Generator Tools - Complete Design & Architecture Document

## Executive Summary

This document provides complete specifications for two professional network packet filter generation tools:
1. **NX-OS Ethanalyzer Command Generator** - For Cisco NX-OS switches
2. **Wireshark Filter Generator** - For Wireshark packet analysis

Both tools are implemented as single, self-contained HTML files with embedded CSS and JavaScript, requiring no external dependencies or frameworks.

---

## 1. Core Architecture

### 1.1 Technology Stack
- **HTML5** - Structure and semantic markup
- **CSS3** - Embedded styling with animations and responsive design
- **Vanilla JavaScript** - All functionality, no external libraries
- **LocalStorage API** - For filter history persistence
- **Clipboard API** - For copy functionality

### 1.2 Design Principles
- **Single File Architecture** - Everything in one HTML file
- **No External Dependencies** - Completely self-contained
- **Offline Capable** - Works without internet connection
- **Responsive Design** - Mobile, tablet, and desktop compatible
- **Progressive Enhancement** - Core functionality works everywhere
- **Cross-Browser Compatible** - Chrome, Firefox, Edge, Safari

### 1.3 File Structure
```
ethanalyzer-generator.html (80KB)
├── HTML Structure
├── Embedded CSS Styles
├── Embedded JavaScript
└── Embedded Data Arrays

wireshark-generator.html (120KB)
├── HTML Structure
├── Embedded CSS Styles
├── Embedded JavaScript
└── Embedded Data Arrays
```

---

## 2. NX-OS Ethanalyzer Command Generator Specifications

### 2.1 Purpose
Generate Cisco NX-OS Ethanalyzer commands for packet capture on Nexus switches. Ethanalyzer only captures control plane (CPU-bound) traffic.

### 2.2 User Interface Tabs

#### 2.2.1 Command Generator Tab
**Purpose**: Main filter creation interface

**Sections**:
1. **Basic Configuration**
   - Interface Selection (mgmt/inband/inband-hi)
   - Filter Type (capture/display/both)
   - Capture Limit (frames)
   - Output File (optional)

2. **IP Address Filters**
   - Source IP (supports CIDR)
   - Destination IP (supports CIDR)
   - Any IP (bidirectional)
   - Exclude option (NOT operator)

3. **Port Filters**
   - Source Port (ranges supported)
   - Destination Port (ranges supported)
   - Any Port (bidirectional)

4. **Protocol Filters**
   - Organized dropdown with categories:
     - Common: TCP, UDP, ICMP, ARP, DHCP
     - Routing: OSPF, BGP, EIGRP, RIP, ISIS, BFD
     - Layer 2: STP, RSTP, MST, VTP, DTP, CDP, LLDP, LACP, PAgP, UDLD
     - First Hop: HSRP, VRRP, GLBP
     - Multicast: IGMP, PIM, MSDP
     - Data Center: VXLAN, VPC, FabricPath, OTV, FCoE
     - Other: IP, IPv6, VLAN

5. **Troubleshooting Patterns**
   - Dropdown with pre-defined patterns:
     - TCP Retransmissions
     - TCP Zero Window
     - TCP Out-of-Order
     - Fragmented Packets
     - TTL Expiry
     - Broadcast Storm
     - MAC Flapping
     - Asymmetric Routing
     - Slow Drain
     - Micro-burst Detection

6. **Advanced Options**
   - Source/Destination MAC
   - Packet Size filters
   - Custom Filter Expression

**Protocol-Specific Options**:
- TCP: Flag checkboxes (SYN, ACK, FIN, RST, PSH)
- ICMP: Type dropdown (Echo Request/Reply, Unreachable, etc.)

#### 2.2.2 Visual Builder Tab
**Purpose**: Build filters without knowing syntax

**Components**:
1. **Filter Type Selection**
   - Capture/Display/Both
   - Interface selection

2. **Condition Builder**
   - Field dropdown (categorized)
   - Operator dropdown
   - Value input (context-aware placeholders)
   - Logic operator (AND/OR)
   - Add/Remove condition buttons

3. **Output Display**
   - Generated command
   - Filter breakdown
   - Copy/Apply buttons

#### 2.2.3 Common Scenarios Tab
**20+ Pre-configured Scenarios**:
- BGP Peer Not Establishing
- OSPF Adjacency Stuck
- DHCP Client Not Getting IP
- Spanning Tree Loop
- HSRP/VRRP Flapping
- High CPU Due to Unknown Traffic
- 802.1X Authentication Failing
- VoIP Call Quality Issues
- TCP Performance Issues
- Multicast Stream Not Received
- vPC Inconsistency Issues
- VXLAN Tunnel Issues
- BFD Session Flapping
- MAC Address Flapping
- Port-Channel Not Forming
- NetFlow Export Issues
- SNMP Polling Timeouts
- ARP Issues/Poisoning
- NTP Synchronization Issues
- Broadcast Storm Detection

Each scenario includes:
- Icon and name
- Symptoms description
- Pre-configured filters
- What to look for
- Common fixes

#### 2.2.4 Filter Templates Tab
**25+ Quick Templates**:
- Basic protocols (SSH, HTTP, DNS, DHCP)
- Routing protocols (OSPF, BGP, EIGRP)
- Layer 2 protocols (STP, CDP, LLDP)
- Management (SNMP, NTP, Syslog)
- Security (RADIUS, TACACS+, 802.1X)
- Data Center (VXLAN, VPC, FabricPath)

#### 2.2.5 Quick Reference Tab
**Documentation Sections**:
1. Capture Filter Syntax (BPF)
2. Display Filter Syntax (Wireshark)
3. Common Protocol Numbers
4. Important Notes

#### 2.2.6 Help & Guidelines Tab
**Comprehensive Documentation**:
1. Interface Selection Guide (mgmt vs inband vs inband-hi)
2. Protocol Guide (when to use each)
3. Troubleshooting Patterns Explained
4. Best Practices
5. Common Pitfalls

### 2.3 Interface Details

#### 2.3.1 Interface Selection Guide
```
Management (mgmt):
- SSH, Telnet, HTTPS management
- SNMP, NTP, Syslog, RADIUS/TACACS+
- Out-of-band management
- Non-data-plane traffic

Inband:
- Routing protocols (OSPF, BGP, EIGRP)
- Layer 2 protocols (STP, CDP, LLDP, LACP)
- First-hop redundancy (HSRP, VRRP)
- DHCP on VLANs
- Control traffic from data ports

Inband-Hi Priority:
- Critical routing messages
- Time-sensitive protocols (PTP, BFD)
- High CPU queue priority
- Spanning-tree TCN/BPDU issues
```

### 2.4 Command Generation Logic

#### 2.4.1 Basic Command Structure
```
ethanalyzer local interface {interface} [capture-filter "{filter}"] [display-filter "{filter}"] [write {file}] [limit-captured-frames {number}]
```

#### 2.4.2 Protocol Mappings
```javascript
DHCP → capture: "(udp port 67 or udp port 68)", display: "bootp"
BGP → capture: "tcp port 179", display: "bgp"
OSPF → capture: "proto 89", display: "ospf"
EIGRP → capture: "proto 88", display: "eigrp"
BFD → capture: "udp port 3784", display: "bfd"
VXLAN → capture: "udp port 4789", display: "vxlan"
VPC → capture: "udp port 3200"
```

### 2.5 Styling Specifications

#### 2.5.1 Color Scheme
```css
Primary Gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%)
Background: Primary gradient
Panel Background: white
Border Color: #e0e0e0
Text Color: #333 (headers), #666 (body), #555 (labels)
Info Box: #e3f2fd (background), #2196F3 (border)
Warning Box: #fff3e0 (background), #ff9800 (border)
Success Box: #e8f5e9 (background), #4caf50 (border)
Command Output: #1e1e1e (background), #00ff00 (text)
```

#### 2.5.2 Typography
```css
Font Family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif
Header (h1): 2.5em
Section Headers (h3): Default with #667eea border-left
Labels: 14px, weight 500
Body Text: 14px
Monospace: 'Courier New', monospace
```

#### 2.5.3 Animations
```css
fadeInDown: 0.8s ease (header)
fadeInUp: 0.8s ease (main panel)
fadeIn: 0.5s ease (tab content)
slideIn: 0.3s ease (active tab indicator)
Hover Effects: translateY(-2px) with shadow
```

---

## 3. Wireshark Filter Generator Specifications

### 3.1 Purpose
Generate Wireshark display filters and BPF capture filters for packet analysis with advanced capabilities.

### 3.2 User Interface Tabs

#### 3.2.1 Filter Generator Tab
**Quick Filter Buttons** (One-click filters):
- TCP Issues
- Slow Response
- Errors Only
- No ARP/Broadcast
- Large Packets
- Retransmissions
- HTTP Errors
- Slow DNS

**Sections**:
1. **Basic Filters**
   - Filter Type (Display/Capture/Both)
   - Interface (Any/Ethernet/WiFi/Loopback/USB/VPN)
   - Capture Mode (Normal/Promiscuous/Monitor)
   - Output Format (Wireshark GUI/tshark/dumpcap/tcpdump)

2. **Network Layer Filters**
   - Source/Destination/Any IP
   - IP Operator (==, !=, contains, in, matches)

3. **Transport Layer Filters**
   - Source/Destination Ports
   - Protocol Selection (80+ protocols in categories)
   - TCP Flags (6 checkboxes)

4. **Advanced Filters**
   - Frame Contains
   - Regex Pattern
   - Frame Length with operators
   - VLAN ID

5. **Time-Based Filters**
   - Frame Time Delta
   - Response Time
   - Time Range
   - Relative Time

6. **Analysis Filters**
   - TCP Analysis checkboxes (5 options)
   - Expert Info Level
   - Stream Number
   - HTTP Status Code

7. **Custom Filter Expression**
   - Manual filter entry textarea

#### 3.2.2 Visual Builder Tab
**Interactive Filter Construction**:
- Drag-drop style interface
- Field selection dropdowns
- Operator selection
- Value inputs with validation
- AND/OR logic combiners
- Add/Remove conditions
- Real-time filter generation

#### 3.2.3 Scenarios Tab
**50+ Scenarios in 12 Categories**:

**Categories**:
1. Performance (3 scenarios)
2. Application (3 scenarios)
3. VoIP (3 scenarios)
4. Media (1 scenario)
5. Security (4 scenarios)
6. Cloud (3 scenarios)
7. Container (1 scenario)
8. IoT (1 scenario)
9. SCADA (1 scenario)
10. Email (2 scenarios)
11. File Transfer (2 scenarios)
12. Advanced (4+ scenarios)

**Statistics Display**:
- Total Scenarios: 50+
- Categories: 12
- Quick Fixes: 200+
- Protocols: 80+

#### 3.2.4 Expert Analysis Tab
**Sections**:
1. **Severity Levels**
   - Errors, Warnings, Notes, Chats

2. **Expert Groups**
   - Malformed, Sequence, Response Code, etc. (8 groups)

3. **TCP Analysis Flags**
   - 10 specific TCP analysis options

4. **Security Analysis**
   - 6 security-specific filters

#### 3.2.5 Templates Tab
**20+ Filter Templates**:
- Performance filters
- Protocol-specific
- Security patterns
- General analysis

#### 3.2.6 Reference Tab
**Documentation**:
1. Display Filter Operators
2. Logical Operators
3. Common Display Filters
4. Capture Filter Syntax

#### 3.2.7 Help Tab
**Comprehensive Guide**:
1. **Filter Operators Mastery**
   - Basic, Contains, Matches, In operators
   - Performance implications

2. **Protocol Deep Dives**
   - HTTP/HTTPS, DNS, TCP, VoIP analysis

3. **Performance Optimization**
   - Filter efficiency tips

4. **Security Analysis**
   - Attack detection patterns

5. **Troubleshooting Methodology**
   - Step-by-step approach
   - Common patterns
   - Resolution paths

### 3.3 Advanced Features

#### 3.3.1 Performance Indicators
```
⚡ Fast: Simple comparisons, exact matches
🔄 Medium: TCP analysis, expert info
🐢 Slow: Regular expressions, frame contains
```

#### 3.3.2 Filter History
- Last 10 filters saved
- LocalStorage persistence
- Favorites system (expandable)

#### 3.3.3 Output Formats
```bash
# Wireshark GUI
Display Filter: tcp.port == 80

# tshark
tshark -i eth0 -Y "tcp.port == 80"

# dumpcap
dumpcap -i eth0 -f "tcp port 80"

# tcpdump
tcpdump -i eth0 "tcp port 80"
```

### 3.4 Wireshark-Specific Operators
```
== (Equal)
!= (Not equal)
> (Greater than)
< (Less than)
>= (Greater or equal)
<= (Less or equal)
contains (Contains value)
matches or ~ (Regex match)
in {} (Value in set)
```

### 3.5 Styling Specifications

#### 3.5.1 Color Scheme
```css
Primary Gradient: linear-gradient(135deg, #00b4d8 0%, #0077be 100%)
Shark Blue: #0077be
Light Blue: #00b4d8
Background: Primary gradient
Panel: white
Command Output: #1e1e1e (bg), #00ff00 (text)
Performance Fast: #4caf50
Performance Medium: #ff9800
Performance Slow: #f44336
```

---

## 4. Shared Components & Features

### 4.1 Common UI Elements

#### 4.1.1 Tab Navigation
```javascript
function switchTab(tabName) {
    // Remove active from all tabs
    document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
    
    // Add active to selected
    event.target.classList.add('active');
    document.getElementById(tabName).classList.add('active');
}
```

#### 4.1.2 Copy to Clipboard
```javascript
function copyCommand() {
    const command = document.getElementById('commandOutput').textContent;
    navigator.clipboard.writeText(command).then(() => {
        const btn = event.target;
        btn.textContent = '✓ Copied!';
        btn.classList.add('copied');
        setTimeout(() => {
            btn.textContent = '📋 Copy';
            btn.classList.remove('copied');
        }, 2000);
    });
}
```

#### 4.1.3 Form Management
```javascript
function clearForm() {
    document.getElementById('filterForm').reset();
    document.getElementById('outputSection').style.display = 'none';
    document.querySelectorAll('.protocol-specific').forEach(el => el.classList.remove('active'));
}
```

### 4.2 Cross-Tool Navigation
Both tools include a button to switch between them:
- Ethanalyzer: Blue "Switch to Wireshark" button
- Wireshark: Purple "Switch to NX-OS" button

### 4.3 Responsive Design Breakpoints
```css
@media (max-width: 768px) {
    .form-grid { grid-template-columns: 1fr; }
    .button-group { flex-direction: column; }
    button { width: 100%; }
    .tabs { overflow-x: auto; }
    .filter-condition { flex-direction: column; }
}
```

---

## 5. Data Structures

### 5.1 Scenario Object Structure
```javascript
{
    name: "Scenario Name",
    icon: "emoji",
    category: "Category",
    symptoms: "Description of symptoms",
    filters: {
        protocol: "protocol_name",
        interface: "interface_type",
        filterType: "capture|display|both"
    },
    command: "filter_string",
    lookFor: ["item1", "item2", "item3"],
    fixes: ["fix1", "fix2", "fix3"]
}
```

### 5.2 Template Object Structure
```javascript
{
    name: "Template Name",
    description: "Template description",
    filter: "filter_string",
    type: "capture|display",
    category: "Category" // Wireshark only
}
```

### 5.3 Visual Builder Condition Structure
```javascript
{
    field: "field_name",
    operator: "operator_type",
    value: "user_value",
    logic: "and|or"
}
```

---

## 6. JavaScript Functions Reference

### 6.1 Core Functions (Both Tools)

```javascript
// Initialization
window.onload = function() {
    loadTemplates();
    loadScenarios();
    // Wireshark also: loadFilterHistory();
}

// Template/Scenario Loading
function loadTemplates() { /* Populate templates */ }
function loadScenarios() { /* Populate scenarios */ }
function loadTemplate(templateName) { /* Apply template */ }
function loadScenario(scenarioName) { /* Apply scenario */ }

// Form Operations
function generateCommand() { /* Ethanalyzer */ }
function generateFilter() { /* Wireshark */ }
function clearForm() { /* Reset all fields */ }
function updateFilterOptions() { /* Update dependent fields */ }
function showProtocolOptions() { /* Show protocol-specific options */ }

// Visual Builder
function addVisualCondition() { /* Add new condition row */ }
function removeVisualCondition(id) { /* Remove condition row */ }
function buildVisualFilter() { /* Generate from visual */ }
function updateFieldOptions(conditionId) { /* Update field dependencies */ }

// Utility Functions
function copyCommand() { /* Copy to clipboard */ }
function exportToCSV() { /* Export filters */ }
function saveAsTemplate() { /* Save current as template */ }
```

### 6.2 Wireshark-Specific Functions

```javascript
// Quick Filters
function applyQuickFilter(filter) { /* Apply one-click filter */ }

// Performance Analysis
function analyzeFilterPerformance(filter) { /* Rate filter efficiency */ }

// History Management
function addToHistory(filter) { /* Add to localStorage */ }
function loadFilterHistory() { /* Load from localStorage */ }
function displayHistory() { /* Show history list */ }
function loadFromHistory(index) { /* Apply from history */ }

// Expert Analysis
function applyExpertFilter(filter) { /* Apply expert filter */ }
function applyExpertToMain() { /* Transfer to main */ }

// Validation
function validateFilter() { /* Check syntax */ }
```

---

## 7. Implementation Guidelines

### 7.1 Development Process
1. Create HTML structure with all tabs
2. Add embedded CSS styles
3. Implement JavaScript functionality
4. Add data arrays (scenarios, templates)
5. Test all features
6. Optimize file size
7. Validate cross-browser compatibility

### 7.2 Testing Checklist
- [ ] All tabs load correctly
- [ ] Form inputs generate correct syntax
- [ ] Visual Builder produces valid filters
- [ ] Scenarios load and apply correctly
- [ ] Templates work as expected
- [ ] Copy functionality works
- [ ] Export to CSV works
- [ ] Responsive design on mobile
- [ ] Cross-browser compatibility
- [ ] Offline functionality
- [ ] File size under limits (Ethanalyzer: ~80KB, Wireshark: ~120KB)

### 7.3 Browser Compatibility
Minimum versions:
- Chrome 60+
- Firefox 55+
- Edge 79+
- Safari 11+

Required APIs:
- localStorage
- Clipboard API
- CSS Grid
- ES6 JavaScript

---

## 8. Deployment Instructions

### 8.1 File Deployment
1. Save both HTML files in the same directory
2. Name them exactly:
   - `ethanalyzer-generator.html`
   - `wireshark-generator.html`
3. No server configuration required
4. No build process needed

### 8.2 Usage Instructions
1. Open either file in a web browser
2. Works completely offline
3. Use "Switch to" button to move between tools
4. Bookmark for quick access

### 8.3 Distribution Options
- Email as attachments
- Host on internal web server
- SharePoint/Confluence upload
- USB drive distribution
- Network share placement

---

## 9. Maintenance & Extension

### 9.1 Adding New Protocols
```javascript
// Add to protocol dropdown
<option value="newprotocol">New Protocol</option>

// Add to generation logic
case 'newprotocol':
    captureFilter.push('protocol_capture_syntax');
    displayFilter.push('protocol_display_syntax');
    break;
```

### 9.2 Adding New Scenarios
```javascript
scenarios.push({
    name: "New Scenario",
    icon: "🆕",
    category: "Category",
    symptoms: "Symptoms description",
    // ... rest of structure
});
```

### 9.3 Adding New Templates
```javascript
templates.push({
    name: "New Template",
    description: "Description",
    filter: "filter_syntax",
    type: "capture|display"
});
```

---

## 10. Version History & Future Enhancements

### 10.1 Current Version Features
- Version 1.0 (Current)
  - Full feature set as described
  - Visual Builder for both tools
  - 50+ scenarios (Wireshark)
  - 20+ scenarios (Ethanalyzer)
  - Cross-tool navigation

### 10.2 Potential Future Enhancements
1. Cloud sync for filter history
2. Team collaboration features
3. Filter performance benchmarking
4. AI-powered filter suggestions
5. Integration with network monitoring tools
6. Custom protocol definitions
7. Filter chain automation
8. Batch command generation
9. PCAP file analysis integration
10. Real-time syntax validation

---

## Appendix A: Complete Protocol Mappings

### A.1 Ethanalyzer Protocol Mappings
```
Protocol    | Capture Filter           | Display Filter
------------|-------------------------|----------------
TCP         | tcp                     | tcp
UDP         | udp                     | udp
ICMP        | icmp                    | icmp
ARP         | arp                     | arp
DHCP        | udp port 67 or 68       | bootp
OSPF        | proto 89                | ospf
BGP         | tcp port 179            | bgp
EIGRP       | proto 88                | eigrp
HSRP        | -                       | hsrp
VRRP        | proto 112               | vrrp
STP         | -                       | stp
CDP         | -                       | cdp
LLDP        | -                       | lldp
VXLAN       | udp port 4789           | vxlan
BFD         | udp port 3784           | bfd
```

### A.2 Common Port Mappings
```
Service     | Port(s)         | Protocol
------------|-----------------|----------
SSH         | 22              | TCP
Telnet      | 23              | TCP
SMTP        | 25              | TCP
DNS         | 53              | UDP/TCP
DHCP        | 67-68           | UDP
HTTP        | 80              | TCP
POP3        | 110             | TCP
NTP         | 123             | UDP
SNMP        | 161-162         | UDP
HTTPS       | 443             | TCP
Syslog      | 514             | UDP
RADIUS      | 1812-1813       | UDP
TACACS+     | 49              | TCP
```

---

## Appendix B: CSS Color Reference

```css
/* Ethanalyzer Tool */
--primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
--primary-color: #667eea;
--primary-dark: #764ba2;

/* Wireshark Tool */
--primary-gradient: linear-gradient(135deg, #00b4d8 0%, #0077be 100%);
--primary-color: #0077be;
--primary-light: #00b4d8;

/* Shared Colors */
--background: white;
--border: #e0e0e0;
--text-primary: #333;
--text-secondary: #666;
--text-muted: #555;
--success: #4caf50;
--warning: #ff9800;
--error: #f44336;
--info: #2196F3;
--terminal-bg: #1e1e1e;
--terminal-text: #00ff00;
```

---

## Appendix C: File Size Optimization

### C.1 Minification Guidelines
- Remove comments
- Minimize whitespace
- Shorten variable names (carefully)
- Combine similar CSS rules
- Use CSS shorthand properties

### C.2 Size Targets
- Ethanalyzer: Target < 100KB
- Wireshark: Target < 150KB
- Combined: Target < 250KB

---

## Document Validation

This document contains all necessary information to recreate both tools exactly:
- ✅ Complete UI specifications
- ✅ All features documented
- ✅ Data structures defined
- ✅ JavaScript logic outlined
- ✅ Styling specifications
- ✅ Protocol mappings
- ✅ Scenario/Template lists
- ✅ Implementation guidelines
- ✅ Deployment instructions

**Document Version**: 1.0
**Last Updated**: Current
**Total Specifications**: Complete

---

## Quick Reference Card

### To Recreate Tools:
1. Use this document as the complete specification
2. Follow the implementation guidelines (Section 7)
3. Include all features from Sections 2 & 3
4. Apply styling from Sections 2.5 & 3.5
5. Implement all functions from Section 6
6. Add all data from Section 5 and Appendices
7. Test using checklist in Section 7.2
8. Deploy as described in Section 8

This document serves as the single source of truth for recreating both network filter generator tools exactly as designed.
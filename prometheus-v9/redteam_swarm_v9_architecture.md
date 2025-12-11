# ACE RedTeam Swarm v9 - Streamlined 4-Agent Architecture

## Overview
RedTeam Swarm v9 represents a refined approach to autonomous red team operations, featuring a **streamlined 4-agent architecture** optimized for web-based penetration testing with clear task segregation and minimal handoff complexity.

## Architecture Principles

### 1. **Simplified Agent Segregation**
Four specialized agents with clear, non-overlapping responsibilities:
- **Red Team Lead**: Strategic planning and coordination
- **Reconnaissance Specialist**: Attack surface mapping and vulnerability discovery
- **Exploiter**: Vulnerability exploitation and initial access
- **Post-Exploit**: Objective completion and impact demonstration

### 2. **Context-Controlled Execution**
- Only the Red Team Lead maintains full operational context
- Specialist agents execute specific tasks and return structured results
- No independent decision-making by specialist agents
- Clear command and control hierarchy

### 3. **Sequential Task Flow**
Natural progression through penetration testing phases:
```
Planning → Reconnaissance → Exploitation → Post-Exploitation
```

## Agent Specifications

### **Red Team Lead** (Strategic Planner)
- **Role**: Mission commander and tactical orchestrator
- **Model**: GPT-4o (16K tokens, temp 0.7)
- **Tools**: None (pure coordination and planning)
- **Handoffs**: 3 specialist delegation handoffs
- **Responsibilities**:
  - Analyze mission objectives and create tactical methodology
  - Break down plans into specific, actionable steps
  - Coordinate specialist activities in sequential phases
  - Maintain full operational context and memory
  - Synthesize results into comprehensive assessments
  - Generate final penetration testing reports

### **Reconnaissance Specialist**
- **MCP**: `reconnaissance_mcp.py`
- **Tools**: Comprehensive reconnaissance and vulnerability discovery tools
  - `nmap_scan` - Network service discovery and port scanning
  - `gobuster_scan` - Directory and subdomain enumeration
  - `nuclei_scan` - Automated vulnerability scanning
  - `ffuf_scan` - Fast web application fuzzing
  - `feroxbuster_scan` - Recursive content discovery
  - `hakrawler_crawl` - Web application crawling and endpoint discovery
  - `paramspider_discovery` - Parameter discovery and analysis
  - `nikto_scan` - Web server vulnerability scanning
  - `whatweb_scan` - Technology stack identification
  - `osint_gathering` - Open source intelligence collection
- **Focus**: Attack surface mapping, vulnerability identification, potential attack path discovery
- **Output**: Structured reconnaissance results with prioritized attack vectors

### **Exploiter**
- **MCP**: `exploiter_mcp.py`
- **Tools**: Exploitation and initial access tools
  - `sqlmap_scan` - SQL injection testing and exploitation
  - `xsser_scan` - Cross-site scripting vulnerability testing
  - `wfuzz_scan` - Web application parameter fuzzing
  - `burpsuite_scan` - Burp Suite integration for manual testing
  - `zap_scan` - OWASP ZAP automated scanning
  - `metasploit_run` - Metasploit framework exploitation
  - `custom_exploit` - Custom exploit development and execution
  - `api_fuzzer` - API endpoint fuzzing and testing
  - `auth_bypass` - Authentication bypass techniques
  - `file_upload_exploit` - File upload vulnerability exploitation
- **Focus**: Vulnerability exploitation, initial access establishment, access validation
- **Output**: Exploitation results with confirmed access methods and system information

### **Post-Exploit**
- **MCP**: `post_exploit_mcp.py`
- **Tools**: Post-exploitation and objective completion tools
  - `execute_command` - System command execution
  - `file_search` - File system search and navigation
  - `privilege_escalation` - Privilege escalation techniques
  - `lateral_movement` - Network lateral movement
  - `credential_harvesting` - Credential extraction and collection
  - `persistence_establishment` - Maintaining access
  - `data_exfiltration` - Data extraction and retrieval
  - `system_enumeration` - Internal system discovery
  - `network_enumeration` - Internal network mapping
  - `objective_completion` - Mission-specific goal achievement
- **Focus**: Objective completion, privilege escalation, impact demonstration
- **Output**: Post-exploitation results with achieved objectives and extracted data

## Operational Workflow

### **Efficiency-Focused Methodology**
The framework employs a **baseline methodology** that prioritizes quick wins and avoids time-consuming rabbit holes:

### 1. **Mission Initialization**
```
User Input → Red Team Lead → Tactical Analysis → Efficiency-Focused Planning
```

### 2. **Rapid Reconnaissance Phase**
```
Red Team Lead → Recon Specialist → Low-Hanging Fruit Discovery → Prioritized Results
```
- **Focus**: Passive recon first, quick scans, automated vulnerability detection
- **Avoid**: Extensive brute forcing unless evidence supports it

### 3. **Targeted Exploitation Phase**
```
Red Team Lead → Exploiter → High-Probability Attacks → Access Validation → Results Return
```
- **Focus**: Known CVEs, default credentials, automated tool results
- **Avoid**: Credential brute forcing without targeted wordlists

### 4. **Efficient Post-Exploitation Phase**
```
Red Team Lead → Post-Exploit → Direct Objective Achievement → Impact Documentation → Results Return
```
- **Focus**: Immediate objective completion, quick privilege escalation
- **Avoid**: Extensive lateral movement unless required

### 5. **Adaptive Decision Making**
```
Continuous Assessment → 15-Minute Rule → Pivot or Continue → Results Synthesis → TERMINATE
```

### **Key Efficiency Principles**
- **15-Minute Rule**: Reassess and pivot if attack vector shows no progress after 15 minutes
- **Evidence-Based Attacks**: Only pursue attacks supported by reconnaissance findings
- **Automated Tools First**: Use automated tools before manual techniques
- **Objective-Focused**: Prioritize attacks that directly achieve mission goals
- **Time-Boxing**: Set limits for complex attack vectors before starting

## Key Improvements Over v7

### **Simplified Architecture**
- **6 agents → 4 agents**: Reduced complexity and handoff overhead
- **Clear task boundaries**: No overlapping responsibilities
- **Sequential execution**: Natural penetration testing flow
- **Centralized context**: Only planner maintains full operational awareness

### **Reduced Handoff Complexity**
- **Minimal context transfer**: Agents execute specific tasks only
- **Structured communication**: Standardized input/output formats
- **No agent-to-agent communication**: All coordination through Red Team Lead
- **Controlled execution**: Agents stop after task completion

### **Enhanced Focus**
- **Web-centric design**: Optimized for web application penetration testing
- **Objective-driven**: Clear mission goals (vulnerability discovery, access, file retrieval)
- **Action-oriented**: Specialist agents are pure execution units
- **Result-focused**: Structured reporting for decision-making

## Communication Protocols

### **Command Structure**
Red Team Lead issues commands using standardized format:
```
AGENT: [recon/exploiter/post-exploit]
TASK: [Specific instruction]
CONTEXT: [Relevant background information]
EXPECTED OUTPUT: [Required result format]
CONSTRAINTS: [Limitations and requirements]
```

### **Response Structure**
Specialist agents return results using standardized format:
```
=== [AGENT TYPE] RESULTS ===
TARGET: [target identifier]
TASK COMPLETED: [description of completed task]

[AGENT-SPECIFIC RESULTS SECTION]

STATUS: [SUCCESS/PARTIAL/FAILED]
NEXT STEPS RECOMMENDED: [suggestions for Red Team Lead]
```

## Security Considerations

### **Operational Security**
- **Controlled execution**: Agents cannot operate independently
- **Centralized logging**: All activities tracked through Red Team Lead
- **Minimal privileges**: Agents operate with task-specific permissions only
- **Contained scope**: No unauthorized expansion of testing scope

### **Tool Security**
- **Sandboxed execution**: Tools run in isolated environments
- **Input validation**: All parameters validated before execution
- **Output sanitization**: Results filtered for sensitive information
- **Error handling**: Graceful failure and recovery mechanisms

## Deployment Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Red Team Lead                            │
│                   (Strategic Planner)                           │
│                 [Maintains Full Context]                        │
└─────────────────────┬───────────────────────────────────────────┘
                      │
        ┌─────────────┼─────────────┐
        │             │             │
┌───────▼──────┐ ┌────▼────┐ ┌─────▼──────┐
│Reconnaissance│ │Exploiter│ │Post-Exploit│
│Specialist    │ │         │ │Specialist  │
│[Task Exec]   │ │[Task    │ │[Task Exec] │
│              │ │ Exec]   │ │            │
└──────────────┘ └─────────┘ └────────────┘
```

## Usage Examples

### **Reconnaissance Request**
```json
{
  "agent": "recon",
  "task": "Conduct comprehensive reconnaissance of target web application",
  "context": "Target: https://example.com, Scope: Web application and API endpoints",
  "expected_output": "Attack surface map with prioritized vulnerabilities",
  "constraints": "Passive reconnaissance only, avoid detection"
}
```

### **Exploitation Request**
```json
{
  "agent": "exploiter", 
  "task": "Exploit identified SQL injection vulnerability",
  "context": "Target: https://example.com/login.php, Parameter: username",
  "expected_output": "Confirmed access with privilege level and session details",
  "constraints": "Minimize system impact, establish stable access"
}
```

### **Post-Exploitation Request**
```json
{
  "agent": "post-exploit",
  "task": "Retrieve local.txt file from compromised system",
  "context": "Access method: SQL injection shell, Current privileges: www-data",
  "expected_output": "File contents and retrieval method documentation",
  "constraints": "Maintain access, avoid detection, document all activities"
}
```

## Working Directory
All operations use: `/home/zeus/prometheus/prometheus-v9`

## Conclusion

ACE RedTeam Swarm v9 delivers a **streamlined, efficient architecture** for web-based penetration testing with clear task segregation, minimal handoff complexity, and centralized operational control.

The 4-agent design provides **optimal balance** between specialization and simplicity, ensuring comprehensive security assessments while maintaining operational efficiency and tactical precision.
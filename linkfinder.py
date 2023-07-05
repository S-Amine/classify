import re
import urllib.request
import gzip
import ssl

def classify_link(result):
    classifications = []

    if result.startswith(('http://', 'https://')):
        classifications.append("HTTP/HTTPS")
    if result.startswith(('wss', 'ws')):
        classifications.append("WebSocket")
    if result.startswith('//'):
        classifications.append("Protocol-relative")
    if result.startswith(('/', '..', '.')) or re.match(r'\w+/[\w/]+', result):
        classifications.append("Relative path")
    if result.startswith(('ftp://', 'ftps://')):
        classifications.append("FTP")
    if result.endswith(('.php', '.asp', '.aspx', '.jsp', '.json', '.action', '.html', '.js', '.txt', '.xml', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.py', '.java', '.cpp', '.c', '.h', '.php', '.html', '.js', '.css', '.exe', '.dll', '.jar')):
        classifications.append("File with extension")
    if result.endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', 'webp')):
        classifications.append("Image file")
    if result.endswith(('.js', '.py', '.java', '.cpp', '.c', '.php', '.html', '.css', '.ps1', '.pl', '.rb', '.sh', '.swift', '.rust', '.go', '.lua', '.typescript', '.r', '.scala', '.perl', '.kotlin', '.matlab', '.groovy', '.haskell', '.dart', '.coffeescript', '.shell', '.powershell', '.vb', '.objective-c', '.groovy', '.fortran', '.elm', '.erlang', '.clojure')):
        classifications.append("Code file")

    languages = {
        r'\.json\b': "Json file",
        r'\.js\b': "JavaScript",
        r'\.py\b': "Python",
        r'\.java\b': "Java",
        r'\.cpp\b': "C++",
        r'\.c\b': "C",
        r'\.php\b': "PHP",
        r'\.html\b': "HTML",
        r'\.css\b': "CSS",
        r'\.ps1\b': "PowerShell",
        r'\.pl\b': "Perl",
        r'\.rb\b': "Ruby",
        r'\.sh\b': "Shell Script",
        r'\.swift\b': "Swift",
        r'\.vb\b': "Visual Basic",
        r'\.lua\b': "Lua",
        r'\.go\b': "Go",
        r'\.rust\b': "Rust",
        r'\.scala\b': "Scala",
        r'\.groovy\b': "Groovy",
        r'\.r\b': "R",
        r'\.matlab\b': "MATLAB",
        r'\.asm\b': "Assembly",
        r'\.vb\b': "Visual Basic",
        r'\.perl\b': "Perl",
        r'\.kotlin\b': "Kotlin",
        r'\.powershell\b': "PowerShell",
        r'\.haskell\b': "Haskell",
        r'\.lua\b': "Lua",
        r'\.typescript\b': "TypeScript",
        r'\.dart\b': "Dart",
        r'\.scala\b': "Scala",
        r'\.groovy\b': "Groovy",
        r'\.cobol\b': "COBOL",
        r'\.swift\b': "Swift",
        r'\.vb\b': "Visual Basic",
        r'\.sql\b': "SQL",
        r'\.rust\b': "Rust",
        r'\.erlang\b': "Erlang",
        r'\.r\b': "R",
        r'\.matlab\b': "MATLAB",
        r'\.asm\b': "Assembly",
        r'\.julia\b': "Julia",
        r'\.dart\b': "Dart",
        r'\.kotlin\b': "Kotlin",
        r'\.powershell\b': "PowerShell",
        r'\.haskell\b': "Haskell",
        r'\.typescript\b': "TypeScript",
        r'\.cobol\b': "COBOL"
    }


    for pattern, language in languages.items():
        if re.search(pattern, result, re.IGNORECASE):
            classifications.append(f"{language} code")

    keywords = {
        r'\b(api|v\d+)\b': "API endpoint",
        r'\b(admin|dashboard)\b': "Administration panel",
        r'\b(login|signin|auth)\b': "Login page",
        r'\b(logout|signout)\b': "Logout page",
        r'\b(upload|file)\b': "File upload",
        r'\b(exploit|vulnerability|attack|payload)\b': "Security-related",
        r'\b(database|db|sql|query)\b': "Database-related",
        r'\b(cdn|contentdeliverynetwork)\b': "CDN",
        r'\b(doc|documentation)\b': "Documentation",
        r'\b(api-docs|apidocs)\b': "API Documentation",
        r'\b(test|demo)\b': "Test/Demo environment",
        r'\b(backup|restore)\b': "Backup/Restore",
        r'\b(source|src)\b': "Source code",
        r'\b(secure|ssl|tls)\b': "Secure connection",
        r'\b(faq|support)\b': "Support/FAQ",
        r'\b(log)\b': "Log files",
        r'\b(config|settings)\b': "Configuration/Settings",
        r'\b(privacy|policy)\b': "Privacy/Policy",
        r'\b(terms|conditions)\b': "Terms/Conditions",
        r'\b(contact|about|info)\b': "Contact/About/Info",
        r'\b(phish|malware|ransomware|botnet|ddos|zero-day)\b': "Cybersecurity threat",
        r'\b(shellshock|heartbleed|spectre|meltdown)\b': "Vulnerability",
        r'\b(pentest|penetrationtesting)\b': "Penetration testing",
        r'\b(firewall|intrusiondetection)\b': "Network security",
        r'\b(antivirus|antimalware)\b': "Malware protection",
        r'\b(encryption|cryptocurrency)\b': "Data protection",
        r'\b(owasp|nist|cve)\b': "Security standards",
        r'\b(incident|securitybreach)\b': "Security incident",
        r'\b(git|gitignore)\b': "Git files",
        r'\b(docker|dockerfile|docker-compose)\b': "Docker files",
        r'\b(\.env)\b': "Environment file",
        r'\b(\readme|README)\b': "README file",
        r'\b(linkedin|facebook|twitter|instagram|youtube|pinterest|tiktok|snapchat|reddit|whatsapp|wechat|telegram|tumblr|vine)\b': "Social media",
        r'\b(password|pass)\b': "Password related",
    }


    for pattern, classification in keywords.items():
        if re.search(pattern, result, re.IGNORECASE):
            classifications.append(classification)

    if not classifications:
        classifications.append("Unknown")

    return classifications



class LinkFinder:
    def __init__(self):
        self.scanned_set = set()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.8',
            'Accept-Encoding': 'gzip'
        }
        ssl._create_default_https_context = ssl._create_unverified_context

    def send_request(self, url):

        q = urllib.request.Request(url, headers=self.headers)
        response = urllib.request.urlopen(q)
        if response.info().get('Content-Encoding') == 'gzip':
            data = gzip.decompress(response.read()).decode('utf-8')
        else:
            data = response.read().decode('utf-8')
        return data


    def get_context(self, list_matches, content):
        items = []
        for m in list_matches:
            item = m[0]
            items.append(item)
        return items


    def parse_file(self, content):
        regex_str = r"""
            (?:"|')                           # Start newline delimiter
            (
                (?:(?:[a-zA-Z]{1,10}://)|//)   # Match a scheme [a-zA-Z]*1-10 or //
                [^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,}  # Match a domainname (any character + dot + domainextension and/or path)
                |
                (?:/|\.\./|\./)                # Start with /,../,./
                [^"'><,;| *()(%%$^/\\\[\]]     # Next character can't be...
                [^"'><,;|()]{1,}               # Rest of the characters can't be
                |
                [a-zA-Z0-9_\-/]{1,}/           # Relative endpoint with /
                [a-zA-Z0-9_\-/]{1,}            # Resource name
                \.(?:[a-zA-Z]{1,4}|action)     # Rest + extension (length 1-4 or action)
                (?:[\?|#][^"|']{0,})           # ? or # mark with parameters
                |
                [a-zA-Z0-9_\-/]{1,}/           # REST API (no extension) with /
                [a-zA-Z0-9_\-/]{3,}            # Proper REST endpoints usually have 3+ chars
                (?:[\?|#][^"|']{0,})           # ? or # mark with parameters
                |
                [a-zA-Z0-9_\-]+                # filename
                \.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)   # . + extension
                (?:[\?|#][^"|']{0,})           # ? or # mark with parameters
            )
            (?:"|')                           # End newline delimiter
        """
        regex = re.compile(regex_str, re.VERBOSE | re.IGNORECASE)
        all_matches = [(m.group(1), m.start(0), m.end(0)) for m in re.finditer(regex, content)]
        items = self.get_context(all_matches, content)
        return items

    def recursive_scan(self, url, depth, principal_domain):
        if url in self.scanned_set or depth < 1:
            return
        self.scanned_set.add(url)

        try:
            file = self.send_request(url)
            self.scanned_set.add(url)  # Move outside the loop to avoid duplicate calls
            endpoints = self.parse_file(file)
            for result in endpoints:
                classification = classify_link(result)
                if 'Image file' not in classification and 'CSS code' not in classification:
                    scan_results = {
                        "link": result,
                        "classification": classification
                    }
                    print(scan_results)

                    if result.startswith('/'):
                        next_url = urllib.parse.urljoin(url, result)
                        self.recursive_scan(next_url, depth - 1, principal_domain)
                    elif result.startswith(('http://', 'https://', 'file://', 'ftp://', 'ftps://')):
                        domain = urllib.parse.urlparse(result).netloc
                        if domain == principal_domain:
                            self.recursive_scan(result, depth - 1, principal_domain)
        except Exception as e:
            print(f"Error scanning {url}: {e}")
            return


    def scan_javascript_files(self, url):
        principal_domain = urllib.parse.urlparse(url).netloc  # Get the principal domain
        self.recursive_scan(url, 2, principal_domain)

link_finder = LinkFinder()
link_finder.scan_javascript_files('https://vulnvision.com')

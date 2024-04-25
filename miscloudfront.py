import argparse
import subprocess
import boto3
import ipaddress
import dns.resolver
import requests
import socket

def get_domains_from_dnsrecon(domain_list):
    additional_domains = set()
    for domain in domain_list:
        try:
            output = subprocess.check_output(["dnsrecon", "-d", domain])
            for line in output.decode().split('\n'):
                if line.startswith('IP'):
                    additional_domains.add(line.split()[1])
        except Exception as e:
            print(f"Error occurred while running dnsrecon for {domain}: {e}")
    return additional_domains

def is_cloudfront_domain(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            ip = ipaddress.ip_address(rdata.address)
            # CloudFront IP ranges as of January 2022
            if any(ip in ipaddress.ip_network(cidr) for cidr in ["13.32.0.0/15", "13.54.0.0/15", "13.249.0.0/16"]):
                return True
    except Exception as e:
        print(f"Error occurred while resolving DNS for {domain}: {e}")
    return False

def test_ssl_certificate(domain):
    try:
        response = requests.get(f"https://{domain}", timeout=5)
        if response.status_code != 200:
            print(f"SSL Certificate Mismatch: {domain}")
    except Exception as e:
        print(f"Error occurred while testing SSL certificate for {domain}: {e}")

def test_cache_control_headers(domain):
    try:
        response = requests.get(f"https://{domain}", timeout=5)
        cache_control = response.headers.get("Cache-Control")
        if not cache_control:
            print(f"Cache Control Headers missing: {domain}")
    except Exception as e:
        print(f"Error occurred while testing cache control headers for {domain}: {e}")

def test_origin_protocol_policy(domain):
    try:
        response = requests.get(f"https://{domain}", timeout=5)
        origin_protocol_policy = response.headers.get("X-Forwarded-Proto")
        if not origin_protocol_policy or origin_protocol_policy != "https":
            print(f"Origin Protocol Policy Misconfigured: {domain}")
    except Exception as e:
        print(f"Error occurred while testing origin protocol policy for {domain}: {e}")

def test_cors_headers(domain):
    try:
        response = requests.get(f"https://{domain}", timeout=5)
        cors_headers = response.headers.get("Access-Control-Allow-Origin")
        if not cors_headers:
            print(f"CORS Headers missing: {domain}")
    except Exception as e:
        print(f"Error occurred while testing CORS headers for {domain}: {e}")

def test_acls(domain):
    try:
        response = requests.get(f"https://{domain}", timeout=5)
        if response.status_code == 403:
            print(f"ACLs Misconfigured: {domain}")
    except Exception as e:
        print(f"Error occurred while testing ACLs for {domain}: {e}")

def test_origin_response_headers(domain):
    try:
        response = requests.get(f"https://{domain}", timeout=5)
        origin_response_headers = response.headers.get("X-Cache")
        if not origin_response_headers:
            print(f"Origin Response Headers Misconfigured: {domain}")
    except Exception as e:
        print(f"Error occurred while testing origin response headers for {domain}: {e}")

def test_ipv6_support(domain):
    try:
        ipv6_address = socket.getaddrinfo(domain, None, socket.AF_INET6)
        if ipv6_address:
            print(f"IPv6 Support Misconfigured: {domain}")
    except Exception as e:
        print(f"Error occurred while testing IPv6 support for {domain}: {e}")

def test_error_pages(domain):
    try:
        response = requests.get(f"https://{domain}/error-page", timeout=5)
        if response.status_code != 200:
            print(f"Error Page Configuration Issue: {domain}")
    except Exception as e:
        print(f"Error occurred while testing error pages for {domain}: {e}")

def test_content_compression(domain):
    try:
        response = requests.get(f"https://{domain}", timeout=5)
        content_encoding = response.headers.get("Content-Encoding")
        if not content_encoding or "gzip" not in content_encoding:
            print(f"Content Compression missing: {domain}")
    except Exception as e:
        print(f"Error occurred while testing content compression for {domain}: {e}")

def test_http_to_https_redirection(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=5, allow_redirects=False)
        if response.status_code == 301 or response.status_code == 302:
            print(f"HTTP to HTTPS Redirection missing: {domain}")
    except Exception as e:
        print(f"Error occurred while testing HTTP to HTTPS redirection for {domain}: {e}")

def test_configuration_issues(domain):
    test_ssl_certificate(domain)
    test_cache_control_headers(domain)
    test_origin_protocol_policy(domain)
    test_cors_headers(domain)
    test_acls(domain)
    test_origin_response_headers(domain)
    test_ipv6_support(domain)
    test_error_pages(domain)
    test_content_compression(domain)
    test_http_to_https_redirection(domain)

def main():
    parser = argparse.ArgumentParser(description='CloudFront Misconfiguration Scanner')
    parser.add_argument('-l', '--target-file', dest='target_file', help='File containing a list of domains (one per line)')
    parser.add_argument('-d', '--domains', dest='domains', help='Comma-separated list of domains to scan')
    parser.add_argument('-o', '--origin', dest='origin', help='Add vulnerable domains to new distributions with this origin')
    parser.add_argument('-i', '--origin-id', dest='origin_id', help='The origin ID to use with new distributions')
    parser.add_argument('-s', '--save', action='store_true', help='Save the results to results.txt')
    parser.add_argument('-N', '--no-dns', action='store_true', help='Do not use dnsrecon to expand scope')

    args = parser.parse_args()

    if args.target_file:
        with open(args.target_file, 'r') as file:
            domains = file.read().splitlines()
    elif args.domains:
        domains = args.domains.split(',')
    else:
        print("Please provide either a target file or a list of domains.")
        return

    if not args.no_dns:
        additional_domains = get_domains_from_dnsrecon(domains)
        domains.extend(additional_domains)

    cloudfront_domains = set()
    for domain in domains:
        if is_cloudfront_domain(domain):
            cloudfront_domains.add(domain)

    for domain in cloudfront_domains:
        print(f"Domain pointing to CloudFront: {domain}")
        test_configuration_issues(domain)

if __name__ == "__main__":
    main()

## CloudFront Misconfiguration Scanner

This script is designed to scan domains for potential misconfigurations related to CloudFront usage. It checks for various issues such as SSL certificate mismatch, cache control headers, CORS headers, ACLs, origin protocol policy, and more.

## Requirements

Python 3.x

dnsrecon (https://github.com/darkoperator/dnsrecon)

Python packages: dns, requests, boto3

You can install Python packages using pip:
pip install -r requirements.txt

Please ensure that dnsrecon is installed and available in your PATH.

## Usage
Command-line options:

-l, --target-file TARGET_FILE: Specifies a file containing a list of domains (one per line) to scan.

-d, --domains DOMAINS: Specifies a comma-separated list of domains to scan.

-o, --origin ORIGIN: Add vulnerable domains to new distributions with this origin.

-i, --origin-id ORIGIN_ID: Specifies the origin ID to use with new distributions.

-s, --save: Save the results to results.txt.

-N, --no-dns: Do not use dnsrecon to expand scope.

## Example usage:

python3 miscloudfront.py -o miscloudfront.com.s3-website-us-east-1.amazonaws.com -i S3-cloudfront -l list.txt

## Disclaimer

This script is provided as-is, without warranty or support. Use it at your own risk.

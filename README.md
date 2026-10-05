## Security Web Scanner
A lightweight FastAPI-based API designed to inspect HTTP security headers of public websites.
## Features
<img width="1902" height="908" alt="image" src="https://github.com/user-attachments/assets/9daa341a-60a0-4041-bacc-d3e61872f860" />


* Validates Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
* Returns identified and missing headers, explicit implementation recommendations, and a security score ranging from 0 to 100.
* Restricts requests exclusively to HTTP/HTTPS protocols and standard ports (80/443).
* Blocks non-public IP addresses (including those resolved via DNS lookups) and validates every redirection hop up to a maximum limit of 5.
* Reads response headers on demand without downloading the full message body.

The generated security score evaluates header presence only rather than individual directive correctness and does not constitute a comprehensive security audit. Strict-Transport-Security is factored into the calculation exclusively for HTTPS endpoints.
## Requirements

* Python 3.10 or newer

## Installation and Execution
Run the following commands from the root directory of the project:

py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
uvicorn app.main:app --reload

Interactive API documentation is accessible at: http://127.0.0.1:8000/docs.
## Usage
Submit a POST /scan request containing the target URL payload:

$body = @{ url = "https://example.com" } | ConvertTo-Json
Invoke-RestMethod -Uri "http://127.0.0.1:8000/scan" -Method Post -ContentType "application/json" -Body $body

The server response returns target_url, security_score, headers_found, headers_missing, and recommendations.
Primary HTTP response status codes: 200 — scan successfully processed; 400 — restricted or unsupported URL; 422 — validation constraint error; 502 — connection failure or bad gateway response from target; 504 — request execution timeout.
## Tests

python -m unittest discover -s tests -v

## Safe Usage Disclaimer
Only execute scans against endpoints you own or have explicit authorization to test. This utility intentionally filters out localhost routing, private subnets, and alternative non-standard port assignments outside of 80 and 443.

# vscan-dns-zone-transfer-checker
Detects DNS zone transfer vulnerabilities by attempting to retrieve zone data from DNS servers. If nameserver discovery fails, for example NXDOMAIN, a timeout, or another resolver error, the tool prints a discovery failure line and exits non-zero, because the check could not run. "Zone transfer vulnerability not found" is reported only after nameservers were found and a transfer was attempted and refused or returned empty. Requires dnspython. - Focused on Lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities

## Install
`git clone https://github.com/ShadowGuardAI/vscan-dns-zone-transfer-checker`

## Usage
`./vscan-dns-zone-transfer-checker [params]`

## Parameters
- `-h`: Show help message and exit

## License
Copyright (c) ShadowGuardAI

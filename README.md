## Security Analysis Features

### MXToolbox-style DNS Analysis

The platform performs domain reputation and email security validation similar to MXToolbox by checking:

- SPF records
- DMARC policies
- MX records
- Sender domain validation
- DNS configuration issues
- Mail routing information

### Google Admin Toolbox-style Header Analysis

The application analyzes raw email headers similar to Google Admin Toolbox:

- Authentication-Results parsing
- SPF validation
- DKIM validation
- DMARC verification
- Received hops analysis
- Return-Path inspection
- Reply-To mismatch detection
- Header anomaly detection

### Threat Intelligence

Integrated threat intelligence sources include:

- VirusTotal URL reputation analysis
- URLScan.io URL inspection
- IOC extraction and investigation
- Suspicious link detection
- Automated phishing indicators

### SOC Workflow Features

- Analyst notes system
- IOC copy/export functionality
- JSON report export
- PDF investigation reports
- SOC dashboard visualization
- Risk scoring system
# 🔒 Security Validated Python Packages

This repository contains Python packages that have been validated through our comprehensive security pipeline.

## 📦 Available Packages
| Package | Version | Validation Date | Quick Install |
|---------|---------|-----------------|---------------|
| `matplotlib` | `3.10.5` | 08.11.25 | `pip install https://github.com/bdousa/pythonFeed/releases/download/matplotlib-v3.10.5/matplotlib-*.whl` |

## 🚀 Usage Instructions
### Option 1: Browse and Download
1. Go to [Releases](https://github.com/bdousa/pythonFeed/releases)
2. Find your package version
3. Download the .whl file
4. Install: `pip install downloaded-package.whl`

### Option 2: Direct Install
Use the quick install commands from the table above.

### Option 3: Requirements File

Create a requirements.txt with direct GitHub URLs:
```
https://github.com/bdousa/pythonFeed/releases/download/requests-v2.32.4/requests-2.32.4-py3-none-any.whl
https://github.com/bdousa/pythonFeed/releases/download/numpy-v1.24.3/numpy-1.24.3-cp311-cp311-linux_x86_64.whl
```

## 🔍 Security Validation Process
All packages in this repository have been validated through our comprehensive security pipeline:
- ✅ **Vulnerability Scanning** - Scanned with Snyk for known CVEs
- ✅ **Source Code Analysis** - Static analysis for security issues
- ✅ **Dependency Analysis** - All dependencies scanned for vulnerabilities
- ✅ **License Compliance** - License compatibility verified
- ✅ **Manual Review** - Security team approval required
- ✅ **Package Integrity** - Cryptographic verification of packages

## 📋 Request New Package Review
To request validation of a new package:
1. **Azure DevOps Request**: Go to [ServiceNow Request Portal](https://bdous.service-now.com/sp?id=sc_cat_item&sys_id=c746dd861b3e6910182c63d07e4bcbac)
2. **Select Category**: Choose '3rd party library approval'
3. **Approval Process**: Packages typically validated within 3 business days

---
*Last updated: 08.11.25 17:31 UTC*
*Powered by Azure DevOps Security Pipeline*

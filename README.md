# 🔒 Security Validated Python Packages

This repository contains Python packages that have been validated through our comprehensive security pipeline.

## 📦 Available Packages
| Package | Version | Validation Date | Quick Install |
|---------|---------|-----------------|---------------|
| `matplotlib` | `3.10.5` | 08.12.25 | `pip install https://github.com/bdousa/pythonFeedWindows/releases/download/matplotlib-v3.10.5/matplotlib-3.10.5-cp313-cp313-win_amd64.whl` |

## 🚀 Usage Instructions
### 🐍 Python 3.13.x Installation Requirements
All packages in this repository require Python 3.13.x for compatibility. If you don't have Python 3.13 installed, follow the instructions below for your platform:

### 🪟 Windows Installation
#### Method 1: Official Python Installer (Recommended)
Download Python 3.13.x from python.org
Run the installer with these important settings:
✅ Check "Add Python to PATH"
✅ Check "Install for all users" (if you have admin rights)
✅ Choose "Customize installation" → Advanced Options → Check "Add Python to environment variables"

### Package Installation Instructions
#### Option 1: Direct Install
Use the quick install commands from the table above.

#### Option 2: Requirements File

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
*Last updated: 08.12.25 10:22 UTC*
*Powered by Azure DevOps Security Pipeline*

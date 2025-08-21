# 🔒 Security Validated Python Packages

This repository contains Python packages that have been validated through our comprehensive security pipeline.

## 📦 Available Packages
| Package | Version | Validation Date | Quick Install |
|---------|---------|-----------------|---------------|
| `pyspark` | `4.0.0` | 08.21.25 | `pip install https://github.com/bdousa/pythonFeedWindows/releases/download/pyspark-v4.0.0/pyspark-4.0.0.tar.gz` |
| `pypdf` | `6.0.0` | 08.21.25 | `pip install https://github.com/bdousa/pythonFeedWindows/releases/download/pypdf-v6.0.0/pypdf-6.0.0-py3-none-any.whl` |
| `azure-datalake-store` | `1.0.1` | 08.21.25 | `pip install https://github.com/bdousa/pythonFeedWindows/releases/download/azure-datalake-store-latest/azure_datalake_store-1.0.1-py2.py3-none-any.whl` |
| `azure-keyvault-secrets` | `4.10.0` | 08.21.25 | `pip install https://github.com/bdousa/pythonFeedWindows/releases/download/azure-keyvault-secrets-latest/azure_keyvault_secrets-4.10.0-py3-none-any.whl` |
| `azure-mgmt-datalake-store` | `0.5.0` | 08.21.25 | `pip install https://github.com/bdousa/pythonFeedWindows/releases/download/azure-mgmt-datalake-store-latest/azure_mgmt_datalake_store-0.5.0-py2.py3-none-any.whl` |
| `azure-storage-blob` | `12.26.0` | 08.21.25 | `pip install https://github.com/bdousa/pythonFeedWindows/releases/download/azure-storage-blob-latest/azure_storage_blob-12.26.0-py3-none-any.whl` |
| `lxml` | `6.0.0` | 08.21.25 | `pip install https://github.com/bdousa/pythonFeedWindows/releases/download/lxml-v6.0.0/lxml-6.0.0-cp313-cp313-win_amd64.whl` |
| `pillow` | `11.3.0` | 08.21.25 | `pip install https://github.com/bdousa/pythonFeedWindows/releases/download/pillow-v11.3.0/pillow-11.3.0-cp313-cp313-win_amd64.whl` |
| `python-dotenv` | `latest` | 08.21.25 | `pip install https://github.com/bdousa/pythonFeedWindows/releases/download/python-dotenv-latest/python_dotenv-1.1.1-py3-none-any.whl` |
| `pythonnet` | `3.0.5` | 08.21.25 | `pip install https://github.com/bdousa/pythonFeedWindows/releases/download/pythonnet-v3.0.5/pythonnet-3.0.5-py3-none-any.whl` |
| `requests` | `2.32.5` | 08.18.25 | `pip install https://github.com/bdousa/pythonFeedWindows/releases/download/requests-v2.32.5/requests-2.32.5-py3-none-any.whl` |
| `tabula-py` | `latest` | 08.18.25 | `pip install https://github.com/bdousa/pythonFeedWindows/releases/download/tabula-py-latest/tabula_py-2.10.0-py3-none-any.whl` |
| `xlrd` | `2.0.2` | 08.18.25 | `pip install https://github.com/bdousa/pythonFeedWindows/releases/download/xlrd-v2.0.2/xlrd-2.0.2-py2.py3-none-any.whl` |
| `chardet` | `5.2.0` | 08.18.25 | `pip install https://github.com/bdousa/pythonFeedWindows/releases/download/chardet-v5.2.0/chardet-5.2.0-py3-none-any.whl` |
| `pytesseract` | `0.3.13` | 08.15.25 | `pip install https://github.com/bdousa/pythonFeedWindows/releases/download/pytesseract-v0.3.13/pytesseract-0.3.13-py3-none-any.whl` |
| `fsspec` | `2025.7.0` | 08.15.25 | `pip install https://github.com/bdousa/pythonFeedWindows/releases/download/fsspec-v2025.7.0/fsspec-2025.7.0-py3-none-any.whl` |
| `pandas` | `2.3.1` | 08.15.25 | `pip install https://github.com/bdousa/pythonFeedWindows/releases/download/pandas-v2.3.1/pandas-2.3.1-cp313-cp313-win_amd64.whl` |
| `numpy` | `2.3.2` | 08.15.25 | `pip install https://github.com/bdousa/pythonFeedWindows/releases/download/numpy-v2.3.2/numpy-2.3.2-cp313-cp313-win_amd64.whl` |
| `matplotlib` | `3.10.5` | 08.12.25 | `pip install https://github.com/bdousa/pythonFeedWindows/releases/download/matplotlib-v3.10.5/matplotlib-3.10.5-cp313-cp313-win_amd64.whl` |

## 🚀 Usage Instructions

### 🐍 Python 3.13.x Installation Requirements
All packages in this repository require Python 3.13.x for compatibility. If you don't have Python 3.13 installed, follow the instructions below for your platform:

### 🪟 Windows Installation

Currently these are all x64 packages, not x86 (32-bit)

#### Official Python Installer

Download Python 3.13.x from python.org

Run the installer with these important settings:
- ✅ Check "Add Python to PATH"
- ✅ Check "Install for all users" (if you have admin rights)
- ✅ Choose "Customize installation" → Advanced Options → Check "Add Python to environment variables"

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
*Last updated: 08.21.25 17:15 UTC*
*Powered by Azure DevOps Security Pipeline*

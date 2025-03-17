# JWT Session Security Analysis Tool

A comprehensive security analysis tool for JWT tokens with an educational focus on session security vulnerabilities.

## Overview

This project provides a suite of tools for analyzing JWT token security, detecting vulnerabilities, and providing educational content on session management best practices. The codebase includes:

1. A JWT token analysis library
2. A full-featured test website for demonstration
3. Tools for generating tokens with various security properties

This tool was designed with an educational focus, making it ideal for learning about JWT security issues and proper implementation.

## Features

- Comprehensive token parsing and validation
- Detection of common JWT security vulnerabilities
- Analysis of token expiration and lifetime issues
- Privilege and permission security scanning
- Threat detection for known attack patterns
- Interactive test website with multiple security levels
- Educational content on security best practices

## Installation

### Prerequisites

- Python 3.8 or higher
- Required packages:
  - PyJWT==2.6.0
  - Flask==2.2.3
  - Werkzeug==2.2.3
  - cryptography==39.0.1
  - requests==2.28.2
  - python-dateutil==2.8.2
  - tabulate==0.9.0
  - colorama==0.4.6 (optional, for colored terminal output)

### Setup

1. Extract the tarball:
   ```
   tar -xzvf jwt-security-tool.tar.gz
   cd jwt-security-tool
   ```

2. Create a virtual environment (recommended):
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install required packages:
   ```
   pip install PyJWT==2.6.0 Flask==2.2.3 Werkzeug==2.2.3 cryptography==39.0.1 requests==2.28.2 python-dateutil==2.8.2 tabulate==0.9.0 colorama==0.4.6
   ```

   We've included a requirements.txt file for convenience:
   ```
   pip install -r requirements.txt
   ```

## Running the Application

### Test Website

The project includes a test website that demonstrates various JWT security features and vulnerabilities:

1. Navigate to the project root directory

2. Run the Flask application:
   ```
   python src/test_website/app.py
   ```

3. Access the website at `http://localhost:5001`

### Token Analysis Tool

You can use the token analysis modules directly in your Python code:

```python
from src.analyzer.session_analyzer import SessionAnalyzer

# Create an analyzer instance
analyzer = SessionAnalyzer()

# Analyze a JWT token
result = analyzer.analyze_token(token_string)

# Print the analysis results
print(result)
```

## Usage Guide

### Test Website

The test website provides several features for exploring JWT security:

1. **Login Page**: Create tokens with different security levels
   - Users: `admin`, `user1`, `guest` (passwords match usernames)
   - Security levels: High, Medium, Low

2. **Dashboard**: View your current token and its properties
   - Decode current token
   - Generate vulnerable tokens for testing
   - Analyze token security

3. **Token Analyzer**: Comprehensive vulnerability scanning
   - Input any JWT token
   - Get detailed security analysis
   - See remediation recommendations

4. **Vulnerable Demo**: Educational demonstrations of common vulnerabilities
   - Weak secret keys
   - Missing expiration
   - HttpOnly flag issues
   - Token manipulation demonstrations

### Security Levels

The application supports three security levels for demonstration purposes:

1. **High Security**:
   - Strong algorithm (HS256)
   - Short expiration (1 hour)
   - HttpOnly flag enabled
   - Secure flag enabled
   - SameSite=Strict

2. **Medium Security**:
   - Strong algorithm (HS256)
   - Longer expiration (24 hours)
   - HttpOnly flag enabled
   - Secure flag disabled
   - SameSite=Lax

3. **Low Security**:
   - Strong algorithm but weak key
   - Very long expiration (7 days)
   - HttpOnly flag disabled
   - Secure flag disabled
   - SameSite not set

## Project Structure

```
SESSION/
├── scripts/
├── src/
│   ├── analyzer/
│   │   ├── __init__.py
│   │   ├── expiration_checker.py
│   │   ├── session_analyzer.py
│   │   ├── threat_detector.py
│   │   ├── token_parser.py
│   │   └── vulnerability_scanner.py
│   ├── test_website/
│   │   ├── templates/
│   │   │   ├── analyzer.html
│   │   │   ├── dashboard.html
│   │   │   ├── index.html
│   │   │   ├── login.html
│   │   │   └── vulnerable.html
│   │   ├── app.py
│   │   └── token_generator.py
│   ├── ui/
│   └── __init__.py
├── tests/
├── README.md
└── requirements.txt
```

## Educational Purpose

This tool is designed for educational purposes to demonstrate JWT security concepts. Some important notes:

- The vulnerable demonstration pages intentionally showcase insecure practices that should never be used in production
- The tool includes the capability to generate tokens with known vulnerabilities for testing and learning
- All code should be considered demonstration-only and not used directly in production systems

## Academic Project

This project was developed as an academic assignment for a computer security course. It demonstrates JWT security concepts and provides tools for analyzing token security in a controlled environment.
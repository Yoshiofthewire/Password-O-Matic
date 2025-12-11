# Password-O-Matic

Password-O-Matic is a secure, web-based password generation tool built with Go. It provides users with a variety of strong and customizable password options suitable for different security and memorability requirements.

## Features

This application offers three distinct password generation modes:

### 1. Normal Passwords
- Purpose: High-security, structured passwords.
- Length: Over 20 characters.
- Structure: Two dictionary words combined with random characters.
- Complexity requirements:
    - At least 2 uppercase letters
    - At least 2 lowercase letters
    - At least 2 numbers
    - At least 2 symbols

### 2. Readable Passwords (Simplified)
- Purpose: Easier to remember while maintaining reasonable complexity.
- Structure: Three dictionary words with random capitalization.
- Complexity: Appended with at least two symbols and a four-digit number (random between 1000 and 9999).

### 3. Random Passwords
- Purpose: Highly unpredictable, fully-random character strings.
- Length: 20–27 characters.
- Complexity requirements:
    - At least 2 uppercase letters
    - At least 2 lowercase letters
    - At least 2 numbers
    - At least 2 symbols

## Prerequisites & Setup

- The web interface is secured via SSL using auto-generated self-signed certificates.
- You must provide a dictionary file named `dictionary.txt`.
    - The file must contain a minimum of 10,000 words for the word-based generators (Normal and Readable) to function correctly.

## Notes
- Self-signed certificates are suitable for local testing or internal use. For production deployment, replace them with certificates issued by a trusted Certificate Authority.
- Ensure `dictionary.txt` is encoded and formatted consistently (one word per line) to avoid issues during password generation.

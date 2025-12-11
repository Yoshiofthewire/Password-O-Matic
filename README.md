Password-O-Matic
Password-O-Matic is a secure, web-based password generation tool built with Go. It provides users with a variety of strong and customizable password options.
Features
This application offers three distinct types of password generation to suit different security and readability needs:
1. Normal Passwords
Normal passwords are designed for high security with a structured approach:
Length: Over 20 characters
Structure: Two words combined with random characters
Complexity: Minimum of:
2 Uppercase letters
2 Lowercase letters
2 Numbers
2 Symbols
2. Readable Passwords (Simplified)
Readable passwords are easier to remember while maintaining complexity:
Structure: Three words with random capitalization
Complexity: Followed by at least two symbols and a four-digit number (between 1000 and 10000)
3. Random Passwords
Random passwords are highly unpredictable character strings:
Length: Between 20 and 27 characters
Complexity: Minimum of:
2 Uppercase letters
2 Lowercase letters
2 Numbers
2 Symbols
Prerequisites and Setup
The web interface is secured by SSL using auto-generated self-signed certificates.
Important Note: You must provide your own dictionary file named dictionary.txt. This file needs to contain a minimum of 10,000 words for the word-based password generators to function correctly.

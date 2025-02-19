# CyberLab - Interactive Security Learning Platform

A web-based platform for learning cybersecurity concepts through hands-on exercises and demonstrations.

## Features

- **Password Strength Analyzer**: Test password strength with real-time feedback
  - Length requirements
  - Character complexity (uppercase, lowercase, numbers, special characters)
  - Visual strength meter
 
![Cybersecurity Demo](https://github.com/DippyM/cyberlab/blob/master/PassAnalyzr.gif)

- **Encryption/Decryption Demo**: Learn about cryptography
  - Symmetric encryption using Fernet
  - Real-time encryption and decryption
  - Key management demonstration
 
![Cybersecurity Demo](https://github.com/DippyM/cyberlab/blob/master/decodr.gif)

- Phishing Awareness Training
- Network Security Basics
- Security Best Practices Guide

## Installation

1. Clone the repository:
```bash
git clone https://github.com/DippyM/cyberlab.git
cd cyberlab
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## Usage

Visit `http://localhost:5000` in your web browser to access the platform.

## Technologies Used

- Flask (Python web framework)
- Cryptography (for encryption/decryption)
- HTML/CSS/JavaScript (frontend)

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

[MIT](https://choosealicense.com/licenses/mit/)

## Security Notice

This platform is for educational purposes only. Do not use any techniques learned here for malicious purposes.

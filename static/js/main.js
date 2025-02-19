// Password Strength Analysis
async function analyzePassword() {
    const password = document.getElementById('passwordInput').value;
    const response = await fetch('/api/analyze-password', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ password })
    });
    
    const data = await response.json();
    
    // Update strength meter
    const strengthFill = document.querySelector('.strength-fill');
    strengthFill.style.width = `${data.strength}%`;
    strengthFill.style.backgroundColor = getStrengthColor(data.strength);
    
    // Update checks
    const checksDiv = document.querySelector('.checks');
    checksDiv.innerHTML = '';
    for (const [check, passed] of Object.entries(data.checks)) {
        const checkItem = document.createElement('div');
        checkItem.className = 'check-item';
        checkItem.innerHTML = `${formatCheckName(check)}: ${passed ? '✓' : '✗'}`;
        checkItem.style.color = passed ? '#00ff00' : '#ff0000';
        checksDiv.appendChild(checkItem);
    }
}

function formatCheckName(check) {
    return check.charAt(0).toUpperCase() + check.slice(1);
}

function getStrengthColor(strength) {
    if (strength < 40) return '#ff0000';
    if (strength < 70) return '#ffff00';
    return '#00ff00';
}

// Encryption/Decryption
async function encryptText() {
    const text = document.getElementById('plaintext').value;
    const response = await fetch('/api/encrypt', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ text })
    });
    
    const data = await response.json();
    document.getElementById('encryptedText').value = data.encrypted;
    document.getElementById('encryptionKey').value = data.key;
}

async function decryptText() {
    const encrypted = document.getElementById('ciphertext').value;
    const key = document.getElementById('decryptKey').value;
    
    const response = await fetch('/api/decrypt', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ encrypted, key })
    });
    
    const data = await response.json();
    if (data.error) {
        document.getElementById('decryptedText').value = 'Error: ' + data.error;
    } else {
        document.getElementById('decryptedText').value = data.decrypted;
    }
}

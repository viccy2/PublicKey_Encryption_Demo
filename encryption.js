let aliceKeyPair;
let bobKeyPair;
let encryptedMessage;

async function generateKeyPairs() {
    try {
        // Generate key pairs for Alice and Bob separately
        aliceKeyPair = await generateKeyPair();
        bobKeyPair = await generateKeyPair();

        // Display public and private keys for Alice and Bob
        document.getElementById("alicePublicKey").value = arrayBufferToBase64(aliceKeyPair.publicKey);
        document.getElementById("alicePrivateKey").value = arrayBufferToBase64(aliceKeyPair.privateKey);
        document.getElementById("bobPublicKey").value = arrayBufferToBase64(bobKeyPair.publicKey);
        document.getElementById("bobPrivateKey").value = arrayBufferToBase64(bobKeyPair.privateKey);
    } catch (error) {
        console.error("Error generating key pairs:", error);
    }
}

async function encryptMessage(sender) {
    try {
        const recipientPublicKey = document.getElementById("publicKeyToEncrypt").value;
        const messageToEncrypt = document.getElementById("messageToEncrypt").value;

        // Convert keys from base64 to ArrayBuffer
        const publicKeyBuffer = base64ToArrayBuffer(recipientPublicKey);

        // Encrypt message using recipient's public key
        encryptedMessage = await encryptMessageWithPublicKey(messageToEncrypt, publicKeyBuffer);

        // Display encrypted message
        document.getElementById("encryptedMessage").value = arrayBufferToBase64(encryptedMessage);

        // Display the appropriate private key for decryption
        if (sender === 'alice') {
            document.getElementById("privateKeyToDecrypt").value = document.getElementById("alicePrivateKey").value;
        } else if (sender === 'bob') {
            document.getElementById("privateKeyToDecrypt").value = document.getElementById("bobPrivateKey").value;
        }
    } catch (error) {
        console.error("Error encrypting message:", error);
    }
}

async function decryptMessage() {
    try {
        const privateKeyToDecrypt = document.getElementById("privateKeyToDecrypt").value;

        // Convert private key from base64 to ArrayBuffer
        const privateKeyBuffer = base64ToArrayBuffer(privateKeyToDecrypt);

        // Decrypt the message using recipient's private key
        const decryptedMessage = await decryptMessageWithPrivateKey(encryptedMessage, privateKeyBuffer);

        // Display decrypted message
        document.getElementById("decryptedMessage").value = decryptedMessage;
    } catch (error) {
        console.error("Error decrypting message:", error);
    }
}

// Function to generate key pair
async function generateKeyPair() {
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
            hash: { name: "SHA-256" },
        },
        true,
        ["encrypt", "decrypt"]
    );
    const publicKey = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
    const privateKey = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
    return { publicKey, privateKey };
}

// Function to encrypt message with public key
async function encryptMessageWithPublicKey(message, publicKey) {
    const encryptedBuffer = await window.crypto.subtle.encrypt(
        {
            name: "RSA-OAEP",
        },
        publicKey,
        new TextEncoder().encode(message)
    );
    return encryptedBuffer;
}

// Function to decrypt message with private key
async function decryptMessageWithPrivateKey(encryptedMessage, privateKey) {
    const decryptedBuffer = await window.crypto.subtle.decrypt(
        {
            name: "RSA-OAEP",
        },
        privateKey,
        encryptedMessage
    );
    return new TextDecoder().decode(decryptedBuffer);
}

// Helper function to convert ArrayBuffer to base64 string
function arrayBufferToBase64(buffer) {
    const binaryArray = new Uint8Array(buffer);
    const binaryString = Array.from(binaryArray, byte => String.fromCharCode(byte)).join('');
    return btoa(binaryString);
}

// Helper function to convert base64 string to ArrayBuffer
function base64ToArrayBuffer(base64) {
    const binaryString = window.atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

let alicePublicKey, bobPublicKey, alicePrivateKey, bobPrivateKey;
// generate keys methods 
async function generateKeyPairs() {
    // Generate key pairs for Alice
    const aliceKeyPair = await generateKeyPair();
    alicePublicKey = aliceKeyPair.publicKey;
    alicePrivateKey = aliceKeyPair.privateKey;
    document.getElementById('alicePublicKey').value = alicePublicKey;
    document.getElementById('alicePrivateKey').value = alicePrivateKey;

    // Generate key pairs for Bob
    const bobKeyPair = await generateKeyPair();
    bobPublicKey = bobKeyPair.publicKey;
    bobPrivateKey = bobKeyPair.privateKey;
    document.getElementById('bobPublicKey').value = bobPublicKey;
    document.getElementById('bobPrivateKey').value = bobPrivateKey;
}
// async methods 
async function generateKeyPair() {
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: {name: "SHA-256"}
        },
        true,
        ["encrypt", "decrypt"]
    );

    const publicKey = await window.crypto.subtle.exportKey(
        "spki",
        keyPair.publicKey
    );

    const privateKey = await window.crypto.subtle.exportKey(
        "pkcs8",
        keyPair.privateKey
    );

    return {
        publicKey: btoa(String.fromCharCode(...new Uint8Array(publicKey))),
        privateKey: btoa(String.fromCharCode(...new Uint8Array(privateKey)))
    };
}

async function encryptMessage() {
    const publicKey = document.getElementById('publicKeyToEncrypt').value;
    const message = document.getElementById('messageToEncrypt').value;
    const encryptedMessage = await encrypt(publicKey, message);
    document.getElementById('encryptedMessage').value = encryptedMessage;
}

async function decryptMessage() {
    const privateKey = document.getElementById('privateKeyToDecrypt').value;
    const encryptedMessage = document.getElementById('messageToDecrypt').value;
    const decryptedMessage = await decrypt(privateKey, encryptedMessage);
    document.getElementById('decryptedMessage').value = decryptedMessage;
}

async function encrypt(recipientPublicKey, message) {
    const messageUint8 = new TextEncoder().encode(message);
    const key = await importPublicKey(recipientPublicKey);

    const encrypted = await window.crypto.subtle.encrypt(
        {
            name: "RSA-OAEP"
        },
        key,
        messageUint8
    );

    return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
}

async function decrypt(privateKey, encryptedMessage) {
    const key = await importPrivateKey(privateKey);
    const encryptedMessageUint8 = Uint8Array.from(atob(encryptedMessage), c => c.charCodeAt(0));

    const decrypted = await window.crypto.subtle.decrypt(
        {
            name: "RSA-OAEP"
        },
        key,
        encryptedMessageUint8
    );

    return new TextDecoder().decode(decrypted);
}

async function importPublicKey(key) {
    const importedKey = await window.crypto.subtle.importKey(
        "spki",
        Uint8Array.from(atob(key), c => c.charCodeAt(0)),
        {
            name: "RSA-OAEP",
            hash: {name: "SHA-256"}
        },
        false,
        ["encrypt"]
    );
    return importedKey;
}

async function importPrivateKey(key) {
    const importedKey = await window.crypto.subtle.importKey(
        "pkcs8",
        Uint8Array.from(atob(key), c => c.charCodeAt(0)),
        {
            name: "RSA-OAEP",
            hash: {name: "SHA-256"}
        },
        false,
        ["decrypt"]
    );
    return importedKey;
}

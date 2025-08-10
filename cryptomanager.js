const crypto = require('crypto');

class CryptoManager {
  constructor() {
    this.rsaKeyPair = null;
    this.peerRsaPublicKey = null;
    // We are now using ECDH instead of DH
    this.ecdh = null;
    this.peerEcdhPublicKey = null; // This will be a Buffer
    this.sharedAesKey = null;

    this.generateRsaKeys();
    // This method is now different
    this.generateEcdhKeys();
  }

  generateRsaKeys() {
    this.rsaKeyPair = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
  }

  // THIS IS THE NEW KEY GENERATION METHOD
  generateEcdhKeys() {
    // We create an Elliptic Curve Diffie-Hellman object using a standard, secure curve
    this.ecdh = crypto.createECDH('prime256v1');
    this.ecdh.generateKeys();
  }

  signData(data) {
    const signer = crypto.createSign('sha256');
    signer.update(data);
    signer.end();
    return signer.sign(this.rsaKeyPair.privateKey);
  }

  verifySignature(data, signature) {
    if (!this.peerRsaPublicKey) return false;
    const verifier = crypto.createVerify('sha256');
    verifier.update(data);
    verifier.end();
    return verifier.verify(this.peerRsaPublicKey, signature);
  }

  generateSharedSecret() {
    if (!this.peerEcdhPublicKey || !this.ecdh) return;
    // The computeSecret method works similarly for ECDH
    this.sharedAesKey = this.ecdh.computeSecret(this.peerEcdhPublicKey);
  }

  encryptMessage(plaintext) {
    if (!this.sharedAesKey) return plaintext;
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.sharedAesKey, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    const tag = cipher.getAuthTag();
    return `${iv.toString('base64')}:${tag.toString('base64')}:${encrypted}`;
  }

  decryptMessage(ciphertextPayload) {
    if (!this.sharedAesKey) return ciphertextPayload;
    try {
      const [ivB64, tagB64, encryptedB64] = ciphertextPayload.split(':');
      const iv = Buffer.from(ivB64, 'base64');
      const tag = Buffer.from(tagB64, 'base64');
      const decipher = crypto.createDecipheriv('aes-256-gcm', this.sharedAesKey, iv);
      decipher.setAuthTag(tag);
      let decrypted = decipher.update(encryptedB64, 'base64', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    } catch (e) {
      console.error("Decryption failed:", e);
      return "--- DECRYPTION FAILED ---";
    }
  }
}

module.exports = CryptoManager;
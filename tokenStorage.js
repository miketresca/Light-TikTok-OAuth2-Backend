const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class SecureTokenStorage {
  constructor(encryptionKey, filePath = './tokens.encrypted.json') {
    this.filePath = filePath;
    
    // Derive a consistent 32-byte key from the encryption key
    if (encryptionKey) {
      // Use scrypt to derive a consistent 32-byte key from the provided key
      // Using a fixed salt ensures the same input key always produces the same output key
      this.encryptionKey = crypto.scryptSync(encryptionKey, 'tiktok-oauth2-salt', 32);
    } else {
      // If no key provided, we need to generate one and store it
      // But this means tokens won't persist across restarts without a key
      console.warn('⚠️  No ENCRYPTION_KEY provided. Tokens will not persist across server restarts.');
      this.encryptionKey = crypto.randomBytes(32);
    }
  }

  // Generate a random encryption key if none provided
  generateEncryptionKey() {
    return crypto.randomBytes(32).toString('hex');
  }

  // Encrypt data
  encrypt(data) {
    const iv = crypto.randomBytes(16); // 16 bytes for AES-256-CBC
    const cipher = crypto.createCipheriv('aes-256-cbc', this.encryptionKey, iv);
    
    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return {
      iv: iv.toString('hex'),
      encrypted: encrypted
    };
  }

  // Decrypt data
  decrypt(encryptedData) {
    try {
      // Validate encrypted data structure
      if (!encryptedData || !encryptedData.iv || !encryptedData.encrypted) {
        console.error('Invalid encrypted data structure');
        return null;
      }

      const iv = Buffer.from(encryptedData.iv, 'hex');
      const decipher = crypto.createDecipheriv('aes-256-cbc', this.encryptionKey, iv);
      
      let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return JSON.parse(decrypted);
    } catch (error) {
      // Provide more helpful error messages
      if (error.message.includes('bad decrypt') || error.message.includes('bad decryption')) {
        console.error('❌ Decryption failed: Invalid encryption key or corrupted data.');
        console.error('   This usually means:');
        console.error('   1. ENCRYPTION_KEY changed since tokens were encrypted, OR');
        console.error('   2. Tokens were encrypted with old/different encryption method');
        console.error('   Solution: Delete tokens.encrypted.json and re-authenticate');
      } else {
        console.error('Decryption failed:', error.message);
      }
      return null;
    }
  }

  // Save tokens to encrypted file
  saveTokens(tokens) {
    try {
      const encrypted = this.encrypt(tokens);
      fs.writeFileSync(this.filePath, JSON.stringify(encrypted));
      console.log('Tokens saved securely');
      return true;
    } catch (error) {
      console.error('Failed to save tokens:', error.message);
      return false;
    }
  }

  // Load tokens from encrypted file
  loadTokens() {
    try {
      if (!fs.existsSync(this.filePath)) {
        console.log('No existing tokens found');
        return null;
      }

      const encryptedData = JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
      const tokens = this.decrypt(encryptedData);
      
      if (tokens) {
        console.log('Tokens loaded successfully');
        return tokens;
      } else {
        console.log('Failed to decrypt tokens');
        return null;
      }
    } catch (error) {
      console.error('Failed to load tokens:', error.message);
      return null;
    }
  }

  // Clear stored tokens
  clearTokens() {
    try {
      if (fs.existsSync(this.filePath)) {
        fs.unlinkSync(this.filePath);
        console.log('Tokens cleared');
      }
      return true;
    } catch (error) {
      console.error('Failed to clear tokens:', error.message);
      return false;
    }
  }

  // Check if tokens exist and are valid
  hasValidTokens() {
    const tokens = this.loadTokens();
    if (!tokens || !tokens.access_token) {
      return false;
    }
    
    // Check if token is expired (with 5 minute buffer)
    const bufferTime = 5 * 60 * 1000; // 5 minutes
    return Date.now() < (tokens.expires_at - bufferTime);
  }
}

module.exports = SecureTokenStorage;
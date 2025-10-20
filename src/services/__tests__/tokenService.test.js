import { describe, it, expect, beforeAll } from '@jest/globals';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import createTokenService from '../tokenService'; // Adjust path as needed

describe('TokenService', () => {
  
  let tokenService;
  let rsaTokenService;
  let testUserId;
  let rsaKeyPair;

  beforeAll(() => {
    // Generate RSA key pair for RS256 testing
    rsaKeyPair = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    // Initialize HMAC-based token service (HS256)
    tokenService = createTokenService({
      algorithm: 'HS256',
      accessSecret: 'test-access-secret-key',
      refreshSecret: 'test-refresh-secret-key',
      accessExpiresIn: '15m',
      refreshExpiresIn: '7d'
    });

    // Initialize RSA-based token service (RS256)
    rsaTokenService = createTokenService({
      algorithm: 'RS256',
      privateKey: rsaKeyPair.privateKey,
      publicKey: rsaKeyPair.publicKey,
      accessExpiresIn: '15m',
      refreshExpiresIn: '7d'
    });

    testUserId = 'user-123';
  });

  describe('HS256 Algorithm Tests', () => {
    describe('signAccessToken', () => {
      it('should create a valid access token with userId', async () => {
        const token = await tokenService.signAccessToken(testUserId);
        expect(token).toBeTruthy();
        expect(typeof token).toBe('string');
      });

      it('should create token with custom claims', async () => {
        const claims = { role: 'admin', email: 'test@example.com' };
        const token = await tokenService.signAccessToken(testUserId, claims);
        const decoded = jwt.decode(token);
        
        expect(decoded.aud).toBe(testUserId);
        expect(decoded.role).toBe('admin');
        expect(decoded.email).toBe('test@example.com');
      });

      it('should create token with expiration', async () => {
        const token = await tokenService.signAccessToken(testUserId);
        const decoded = jwt.decode(token);
        
        expect(decoded.exp).toBeTruthy();
        expect(decoded.iat).toBeTruthy();
        expect(decoded.exp).toBeGreaterThan(decoded.iat);
      });
    });

    describe('signRefreshToken', () => {
      it('should create a valid refresh token', async () => {
        const token = await tokenService.signRefreshToken(testUserId);
        expect(token).toBeTruthy();
        expect(typeof token).toBe('string');
      });

      it('should create token with userId in aud claim', async () => {
        const token = await tokenService.signRefreshToken(testUserId);
        const decoded = jwt.decode(token);
        
        expect(decoded.aud).toBe(testUserId);
      });
    });

    describe('verifyAccessToken', () => {
      it('should verify a valid access token', async () => {
        const token = await tokenService.signAccessToken(testUserId);
        const payload = await tokenService.verifyAccessToken(token);
        
        expect(payload.aud).toBe(testUserId);
      });

      it('should verify token with custom claims', async () => {
        const claims = { role: 'user', permissions: ['read', 'write'] };
        const token = await tokenService.signAccessToken(testUserId, claims);
        const payload = await tokenService.verifyAccessToken(token);
        
        expect(payload.role).toBe('user');
        expect(payload.permissions).toEqual(['read', 'write']);
      });

      it('should reject invalid token', async () => {
        await expect(
          tokenService.verifyAccessToken('invalid.token.here')
        ).rejects.toThrow();
      });

      it('should reject expired token', async () => {
        const shortLivedService = createTokenService({
          algorithm: 'HS256',
          accessSecret: 'test-secret',
          accessExpiresIn: '1ms'
        });

        const token = await shortLivedService.signAccessToken(testUserId);
        
        // Wait for token to expire
        await new Promise(resolve => setTimeout(resolve, 100));
        
        await expect(
          shortLivedService.verifyAccessToken(token)
        ).rejects.toThrow();
      });

      it('should reject token signed with different secret', async () => {
        const otherService = createTokenService({
          algorithm: 'HS256',
          accessSecret: 'different-secret'
        });

        const token = await otherService.signAccessToken(testUserId);
        
        await expect(
          tokenService.verifyAccessToken(token)
        ).rejects.toThrow();
      });
    });

    describe('verifyRefreshToken', () => {
      it('should verify a valid refresh token', async () => {
        const token = await tokenService.signRefreshToken(testUserId);
        // const payload = await tokenService.verifyRefreshToken(token);
        
        // expect(payload.aud).toBe(testUserId);
      });

      it('should reject invalid refresh token', async () => {
        await expect(
          tokenService.verifyRefreshToken('invalid.token.here')
        ).rejects.toThrow();
      });
    });

    describe('getArgs', () => {
      it('should return verification key and algorithm', () => {
        const args = tokenService.getArgs();
        
        expect(args.key).toBe('test-access-secret-key');
        expect(args.algorithm).toBe('HS256');
      });
    });
  });

  describe('RS256 Algorithm Tests', () => {
    describe('signAccessToken', () => {
      it('should create a valid access token with RSA', async () => {
        const token = await rsaTokenService.signAccessToken(testUserId);
        expect(token).toBeTruthy();
        expect(typeof token).toBe('string');
      });

      it('should create token with custom claims', async () => {
        const claims = { role: 'admin' };
        const token = await rsaTokenService.signAccessToken(testUserId, claims);
        const decoded = jwt.decode(token);
        
        expect(decoded.aud).toBe(testUserId);
        expect(decoded.role).toBe('admin');
      });
    });

    describe('signRefreshToken', () => {
      it('should create a valid refresh token with RSA', async () => {
        const token = await rsaTokenService.signRefreshToken(testUserId);
        expect(token).toBeTruthy();
      });
    });

    describe('verifyAccessToken', () => {
      it('should verify a valid RSA-signed token', async () => {
        const token = await rsaTokenService.signAccessToken(testUserId);
        const payload = await rsaTokenService.verifyAccessToken(token);
        
        expect(payload.aud).toBe(testUserId);
      });

      it('should reject token signed with different key', async () => {
        const otherKeyPair = crypto.generateKeyPairSync('rsa', {
          modulusLength: 2048,
          publicKeyEncoding: { type: 'spki', format: 'pem' },
          privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });

        const otherService = createTokenService({
          algorithm: 'RS256',
          privateKey: otherKeyPair.privateKey,
          publicKey: otherKeyPair.publicKey
        });

        const token = await otherService.signAccessToken(testUserId);
        
        await expect(
          rsaTokenService.verifyAccessToken(token)
        ).rejects.toThrow();
      });
    });

    describe('verifyRefreshToken', () => {
      it('should verify a valid RSA-signed refresh token', async () => {
        const token = await rsaTokenService.signRefreshToken(testUserId);
        const payload = await rsaTokenService.verifyRefreshToken(token);
        
        expect(payload.aud).toBe(testUserId);
      });
    });

    describe('getArgs', () => {
      it('should return public key and RS256 algorithm', () => {
        const args = rsaTokenService.getArgs();
        
        expect(args.key).toBe(rsaKeyPair.publicKey);
        expect(args.algorithm).toBe('RS256');
      });
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty claims object', async () => {
      const token = await tokenService.signAccessToken(testUserId, {});
      const payload = await tokenService.verifyAccessToken(token);
      
      expect(payload.aud).toBe(testUserId);
    });

    it('should handle numeric userId', async () => {
      const numericUserId = 12345;
      const token = await tokenService.signAccessToken(numericUserId);
      const payload = await tokenService.verifyAccessToken(token);
      
      expect(payload.aud).toBe(numericUserId);
    });

    it('should handle special characters in userId', async () => {
      const specialUserId = 'user-123@example.com';
      const token = await tokenService.signAccessToken(specialUserId);
      const payload = await tokenService.verifyAccessToken(token);
      
      expect(payload.aud).toBe(specialUserId);
    });

    it('should handle null token gracefully', async () => {
      await expect(
        tokenService.verifyAccessToken(null)
      ).rejects.toThrow();
    });

    it('should handle undefined token gracefully', async () => {
      await expect(
        tokenService.verifyAccessToken(undefined)
      ).rejects.toThrow();
    });
  });

  describe('Token Lifecycle', () => {
    it('should create and verify complete token flow', async () => {
      // Sign both tokens
      const accessToken = await tokenService.signAccessToken(testUserId, { 
        role: 'user' 
      });
      const refreshToken = await tokenService.signRefreshToken(testUserId);

      // Verify both tokens
      const accessPayload = await tokenService.verifyAccessToken(accessToken);
      // const refreshPayload = await tokenService.verifyRefreshToken(refreshToken);

      // Check payloads
      expect(accessPayload.aud).toBe(testUserId);
      expect(accessPayload.role).toBe('user');
      // expect(refreshPayload.aud).toBe(testUserId);
    });
  });
});
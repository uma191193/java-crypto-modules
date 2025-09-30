/*
package jjwt_13;

import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.util.Date;

*/
/**
 * Demonstrates using JJWT 0.13.0 to:
 * 1. Generate symmetric (HMAC) and asymmetric (RSA) keys
 * 2. Create and sign a JWT (JWS)
 * 3. Verify the signed JWT and handle expiration
 * 4. Encrypt a JWT (JWE)
 * 5. Decrypt the JWE
 * 6. Verify encryption-decryption integrity
 *//*

public class JjwtCryptoSample_13 {

    private static final Logger logger = LoggerFactory.getLogger(JjwtCryptoSample_13.class);

    public static void main(String[] args) {
        try {
            // ============================================================
            // Step 1: Generate Keys (Symmetric & Asymmetric)
            // ============================================================
            */
/*
             * Symmetric key (SecretKey) for signing JWTs (JWS) using HS256:
             * - HS256 uses HMAC + SHA-256
             * - Same key is used for signing and verification
             *//*

            SecretKey hmacKey = Jwts.SIG.HS256.key().build();

            */
/*
             * Asymmetric RSA key pair for encrypting JWTs (JWE) using RSA-OAEP + AES-256-GCM:
             * - Public key: used to encrypt the JWT
             * - Private key: used to decrypt the JWT
             * - Safer for multi-party systems because private key is not shared
             *//*

            KeyPair rsaKeyPair = Jwts.SIG.RS256.keyPair().build();

            // Define "issued at" (iat) and "expiration" (exp) claims
            Date now = new Date(); // current timestamp
            Date expiry = new Date(System.currentTimeMillis() + 5000); // token valid for 5 seconds

            // ============================================================
            // Step 2: Create & Sign a JWT (JWS)
            // ============================================================
            */
/*
             * Creating a JWS (JSON Web Signature):
             * - Protects the integrity of the token (any tampering is detectable)
             * - Claims:
             *   - "sub": subject (who/what the token is about)
             *   - "iat": issued at
             *   - "exp": expiration
             * - Signed using the symmetric HMAC key (HS256)
             * - Resulting compact JWT has 3 parts: header.payload.signature
             *//*

            String jws = Jwts.builder()
                    .claim("sub", "crypto-demo")
                    .issuedAt(now)
                    .expiration(expiry)
                    .signWith(hmacKey)
                    .compact();

            logger.info("Signed JWS (expires at {}): {}", expiry, jws);

            // ============================================================
            // Step 3: Simulate token expiration
            // ============================================================
            */
/*
             * To demonstrate ExpiredJwtException handling, sleep > token expiry
             * This simulates trying to parse an expired token
             *//*

            logger.info("Sleeping 6 seconds so tokens expire...");
            Thread.sleep(6000);

            // ============================================================
            // Step 4: Verify Signed JWT (JWS Parsing)
            // ============================================================
            try {
                */
/*
                 * Parsing and verifying a JWS:
                 * - .verifyWith(hmacKey): must use the same key used to sign
                 * - .parseSignedClaims(jws): validates signature and expiration
                 *
                 * Exceptions:
                 * - ExpiredJwtException: thrown if token has expired
                 * - JwtException: thrown for invalid signature, malformed token, etc.
                 *//*

                Jws<Claims> parsedJws = Jwts.parser()
                        .verifyWith(hmacKey)
                        .build()
                        .parseSignedClaims(jws);

                logger.info("Verified JWS subject: {}", parsedJws.getPayload().getSubject());

            } catch (ExpiredJwtException e) {
                logger.warn("JWS expired at {}: {}", e.getClaims().getExpiration(), e.getMessage());
            } catch (JwtException e) {
                logger.error("JWS verification failed: {}", e.getMessage(), e);
            }

            // ============================================================
            // Step 5: Encrypt a JWT (JWE)
            // ============================================================
            */
/*
             * Creating a JWE (JSON Web Encryption):
             * - Protects confidentiality: payload cannot be read without the private key
             * - Uses two algorithms:
             *   - Key Management: RSA-OAEP (asymmetric)
             *     → encrypts a randomly generated AES key with public key
             *   - Content Encryption: AES-256-GCM (symmetric)
             *     → encrypts the payload securely
             * - Claims:
             *   - "sub": subject
             *   - "iat": issued at
             *   - "exp": expiration
             * - Output: compact JWT with 5 parts: header.encryptedKey.iv.ciphertext.tag
             *//*

            String originalSubject = "encrypted-demo"; // store original claim for verification

            String jwe = Jwts.builder()
                    .claim("sub", originalSubject)
                    .issuedAt(now)
                    .expiration(expiry)
                    .encryptWith(
                            rsaKeyPair.getPublic(),
                            Jwts.KEY.RSA_OAEP,
                            Jwts.ENC.A256GCM
                    )
                    .compact();

            logger.info("Encrypted JWE (expires at {}): {}", expiry, jwe);

            // ============================================================
            // Step 6: Decrypt the JWE
            // ============================================================
            try {
                */
/*
                 * Parsing and decrypting a JWE:
                 * - .decryptWith(privateKey, keyAlgorithm, encAlgorithm)
                 *   → must use the private key corresponding to public key used to encrypt
                 * - .parseEncryptedClaims(jwe)
                 *
                 * Exceptions:
                 * - ExpiredJwtException: token expired
                 * - JwtException: decryption error, wrong key, tampered token
                 *//*

                Jwe<Claims> decrypted = Jwts.parser()
                        .decryptWith(rsaKeyPair.getPrivate())
                        .build()
                        .parseEncryptedClaims(jwe);

                String decryptedSubject = decrypted.getPayload().get("sub", String.class);
                logger.info("Decrypted JWE subject: {}", decryptedSubject);

                // ============================================================
                // Step 7: Verify Decrypted Claim Matches Original
                // ============================================================
                */
/*
                 * Ensure that the decrypted payload matches the original input:
                 * - Helps detect tampering or errors in encryption/decryption process
                 *//*

                if (originalSubject.equals(decryptedSubject)) {
                    logger.info("SUCCESS: Decrypted claim matches the original claim.");
                } else {
                    logger.error("FAILURE: Decrypted claim does NOT match the original claim!");
                }

            } catch (ExpiredJwtException e) {
                logger.warn("JWE expired at {}: {}", e.getClaims().getExpiration(), e.getMessage());
            } catch (JwtException e) {
                logger.error("JWE decryption failed: {}", e.getMessage(), e);
            }

        } catch (Exception e) {
            logger.error("Unexpected error occurred: {}", e.getMessage(), e);
        }
    }
}*/

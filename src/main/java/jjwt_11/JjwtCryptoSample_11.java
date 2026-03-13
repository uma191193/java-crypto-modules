/*
package jjwt_11;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.util.Date;

/**
 * Demonstrates how to use JJWT 0.11.5 with Java 24 for:
 * 1. Generating symmetric (HMAC) and asymmetric (RSA) keys
 * 2. Creating and signing JWTs (JWS)
 * 3. Parsing and verifying signed JWTs
 * 4. Handling token expiration and tampering
 * NOTE: JJWT 0.11.5 does NOT support JWE (encryption/decryption).
 * Only signed JWTs (JWS) are demonstrated here.
 * /
public class JjwtCryptoSample_11 {

    private static final Logger logger = LoggerFactory.getLogger(JjwtCryptoSample_11.class);

    public static void main(String[] args) {
        try {
            // ============================================================
            // Step 1: Generate Keys
            // ============================================================

            /*
             * Symmetric key for HS256 (HMAC with SHA-256).
             * Same key is used for both signing and verifying.
             * /
            SecretKey hmacKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);

            /*
             * Asymmetric RSA key pair for RS256 (RSA + SHA-256).
             * Private key: used to sign the token.
             * Public key: used to verify the token.
             * /
            KeyPair rsaKeyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);

            // Define issued-at and expiration timestamps
            Date now = new Date(); // "iat"
            Date expiry = new Date(System.currentTimeMillis() + 5000); // "exp" (valid for 5 seconds)

            // ============================================================
            // Step 2: Create & Sign a JWT with HMAC
            // ============================================================

            /*
             * Building a JWT signed with HS256:
             * - Subject: "hmac-demo"
             * - IssuedAt + Expiration
             * - Signed with secret key
             * /
            String hmacJws = Jwts.builder()
                    .setSubject("hmac-demo")
                    .setIssuedAt(now)
                    .setExpiration(expiry)
                    .signWith(hmacKey, SignatureAlgorithm.HS256) // explicit algorithm required
                    .compact();

            logger.info("Signed HMAC JWS (expires at {}): {}", expiry, hmacJws);

            // ============================================================
            // Step 3: Create & Sign a JWT with RSA
            // ============================================================

            /*
             * Building a JWT signed with RS256:
             * - Subject: "rsa-demo"
             * - Uses RSA private key for signing
             * /
            String rsaJws = Jwts.builder()
                    .setSubject("rsa-demo")
                    .setIssuedAt(now)
                    .setExpiration(expiry)
                    .signWith(rsaKeyPair.getPrivate(), SignatureAlgorithm.RS256)
                    .compact();

            logger.info("Signed RSA JWS (expires at {}): {}", expiry, rsaJws);

            // ============================================================
            // Step 4: Simulate token expiration
            // ============================================================

            logger.info("Sleeping 6 seconds so both tokens expire...");
            Thread.sleep(6000); // wait long enough for "exp" to pass

            // ============================================================
            // Step 5: Parse & Verify HMAC JWS
            // ============================================================

            try {
                /*
                 * Parsing HMAC JWS:
                 * - Uses the same secret key that was used to sign.
                 * - Automatically verifies signature and expiration.
                 *
                 * Possible exceptions:
                 * - ExpiredJwtException: if token is expired
                 * - JwtException: if signature is invalid, or token is malformed
                 * /
                Jws<Claims> parsedHmac = Jwts.parserBuilder()
                        .setSigningKey(hmacKey)
                        .build()
                        .parseClaimsJws(hmacJws);

                logger.info("Verified HMAC JWS subject: {}", parsedHmac.getBody().getSubject());

            } catch (ExpiredJwtException e) {
                logger.warn("HMAC JWS expired at {}: {}", e.getClaims().getExpiration(), e.getMessage());
            } catch (JwtException e) {
                logger.error("HMAC JWS verification failed: {}", e.getMessage(), e);
            }

            // ============================================================
            // Step 6: Parse & Verify RSA JWS
            // ============================================================

            try {
                /*
                 * Parsing RSA JWS:
                 * - Uses the public key corresponding to the private key used for signing.
                 * /
                Jws<Claims> parsedRsa = Jwts.parserBuilder()
                        .setSigningKey(rsaKeyPair.getPublic())
                        .build()
                        .parseClaimsJws(rsaJws);

                logger.info("Verified RSA JWS subject: {}", parsedRsa.getBody().getSubject());

            } catch (ExpiredJwtException e) {
                logger.warn("RSA JWS expired at {}: {}", e.getClaims().getExpiration(), e.getMessage());
            } catch (JwtException e) {
                logger.error("RSA JWS verification failed: {}", e.getMessage(), e);
            }

            // ============================================================
            // Step 7: Demonstrate Token Tampering Detection
            // ============================================================

            try {
                // Take a valid token and "tamper" with its content (simulate attacker)
                String tamperedJws = hmacJws.substring(0, hmacJws.length() - 2) + "xx";

                logger.info("Tampered JWS: {}", tamperedJws);

                // Try parsing the tampered token
                Jwts.parserBuilder()
                        .setSigningKey(hmacKey)
                        .build()
                        .parseClaimsJws(tamperedJws);

                logger.error("Tampered token was unexpectedly verified!");

            } catch (JwtException e) {
                logger.info("Tampered token correctly rejected: {}", e.getMessage());
            }

        } catch (Exception e) {
            logger.error("Unexpected error in demo: {}", e.getMessage(), e);
        }
    }
}
*/
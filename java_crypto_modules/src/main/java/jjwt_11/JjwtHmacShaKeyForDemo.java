/*
package jjwt_11;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.util.Date;

*/
/**
 * Java 24 + JJWT 0.11.5 Demo: Using Keys.hmacShaKeyFor for HMAC JWTs
 * using a single JWT builder and inline verification.
 * Key Points:
 * 1. hmacShaKeyFor(byte[] keyBytes) converts raw bytes into a SecretKey for HMAC signing.
 * 2. HMAC algorithms supported by JJWT: HS256, HS384, HS512.
 * 3. Recommended minimum key lengths:
 * - HS256: 32 bytes (256 bits)
 * - HS384: 48 bytes (384 bits)
 * - HS512: 64 bytes (512 bits)
 * Using shorter keys reduces security and may throw exceptions in recent JJWT versions.
 * 4. The same key can technically be used across algorithms, but it's safer to match key length with algorithm strength.
 * 5. JWT signing requires:
 * - Claims (payload) like subject, issuedAt, expiration.
 * - A SecretKey and SignatureAlgorithm.
 * 6. JWT parsing and verification:
 * - Checks signature integrity using the same key.
 * - Automatically checks token expiration.
 * - Throws exceptions for expired or tampered tokens.
 *//*

public class JjwtHmacShaKeyForDemo {

    private static final Logger logger = LoggerFactory.getLogger(JjwtHmacShaKeyForDemo.class);

    public static void main(String[] args) throws InterruptedException {
        try {
            // ============================================================
            // Step 1: Create a SecretKey using hmacShaKeyFor
            // ============================================================

            // Raw secret key bytes (example only; in production, use secure storage)
            byte[] rawKeyBytes = "my-super-secret-key-my-super-secret-key-my-super-secret".getBytes();

            // Converts byte array into a SecretKey for HMAC signing
            SecretKey hmacKey = Keys.hmacShaKeyFor(rawKeyBytes);

            */
/*
             * Choosing the algorithm:
             * - HS256: secure, widely used, minimum 32 bytes
             * - HS384: stronger than HS256, minimum 48 bytes
             * - HS512: strongest HMAC, minimum 64 bytes
             *
             * When building the JWT, you select the algorithm. The SecretKey must meet the algorithm's size requirement.
             *//*


            // ============================================================
            // Step 2: Build & sign a JWT (single builder example)
            // ============================================================

            Date now = new Date();
            Date expiry = new Date(System.currentTimeMillis() + 5000); // token valid for 5 seconds

            String jws = Jwts.builder()
                    .setSubject("hmac-demo") // identifies the principal or purpose
                    .setIssuedAt(now)         // "iat" claim
                    .setExpiration(expiry)    // "exp" claim
                    .signWith(hmacKey, SignatureAlgorithm.HS256) // signing algorithm-HS256
                    //.signWith(hmacKey, SignatureAlgorithm.HS384) // signing algorithm-HS384
                    //.signWith(hmacKey, SignatureAlgorithm.HS512) // signing algorithm-HS512
                    .compact();

            logger.info("Signed JWS: {}", jws);

            // ============================================================
            // Step 3: Parse & verify JWT inline
            // ============================================================
            try {
                // Parsing checks:
                // 1. Signature validity
                // 2. Expiration (automatically)
                Jws<Claims> parsed = Jwts.parserBuilder()
                        .setSigningKey(hmacKey)
                        .build()
                        .parseClaimsJws(jws);

                logger.info("Verified JWT subject: {}", parsed.getBody().getSubject());
            } catch (ExpiredJwtException e) {
                logger.warn("Token expired at {}: {}", e.getClaims().getExpiration(), e.getMessage());
            } catch (JwtException e) {
                logger.error("JWT verification failed (tampered or invalid): {}", e.getMessage());
            } catch (Exception e) {
                logger.error("Unexpected error during verification: {}", e.getMessage(), e);
            }

            // ============================================================
            // Step 4: Simulate token expiration
            // ============================================================
            logger.info("Sleeping 6 seconds to let token expire...");
            Thread.sleep(6000);

            try {
                Jwts.parserBuilder()
                        .setSigningKey(hmacKey)
                        .build()
                        .parseClaimsJws(jws);

                logger.info("Token still valid after expiration time!"); // should not happen
            } catch (ExpiredJwtException e) {
                logger.warn("Token expired as expected at {}: {}", e.getClaims().getExpiration(), e.getMessage());
            } catch (JwtException e) {
                logger.error("JWT verification failed: {}", e.getMessage());
            }

            // ============================================================
            // Step 5: Demonstrate tampering detection inline
            // ============================================================
            try {
                // Simulate an attacker modifying the token
                String tamperedJws = jws.substring(0, jws.length() - 2) + "xx";
                logger.info("Tampered JWS: {}", tamperedJws);

                // Parsing a tampered token throws JwtException
                Jwts.parserBuilder()
                        .setSigningKey(hmacKey)
                        .build()
                        .parseClaimsJws(tamperedJws);

                logger.error("Tampered token was unexpectedly verified!");
            } catch (JwtException e) {
                logger.info("Tampered token correctly rejected: {}", e.getMessage());
            } catch (Exception e) {
                logger.error("Unexpected error during tamper test: {}", e.getMessage(), e);
            }

        } catch (Exception e) {
            logger.error("Unexpected error in demo: {}", e.getMessage(), e);
        }
    }
}*/

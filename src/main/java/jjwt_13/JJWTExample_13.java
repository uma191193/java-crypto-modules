package jjwt_13;

// Import necessary JJWT classes

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.util.Date;

public class JJWTExample_13 {

    public static void main(String[] args) {

        // ======================================
        // 1. Generate Secret Key for HS256
        // ======================================

        /*
         * The `Jwts.SIG.HS256.key().build()` method generates a secure 256-bit key suitable for HMAC-SHA256 (HS256).
         *
         * 🔐 HMAC (symmetric) algorithms:
         * - HS256: HMAC using SHA-256 (32-byte key)
         * - HS384: HMAC using SHA-384 (48-byte key)
         * - HS512: HMAC using SHA-512 (64-byte key)
         *
         * To generate keys for other HMAC algorithms:
         * SecretKey key = Jwts.SIG.HS384.key().build();
         * SecretKey key = Jwts.SIG.HS512.key().build();
         */
        SecretKey key = Jwts.SIG.HS256.key().build();

        // ======================================
        // 2. Generate KeyPair for RS/PS Algorithms (Asymmetric)
        // ======================================

        /*
         * `Jwts.SIG.PS512.keyPair().build()` generates an RSA key pair for RSASSA-PSS using SHA-512 (PS512).
         *
         * 🔐 Supported Asymmetric Algorithms:
         * - RS256 / RS384 / RS512 : RSA with PKCS#1 v1.5
         * - PS256 / PS384 / PS512 : RSA with PSS padding
         * - ES256 / ES384 / ES512 : Elliptic Curve Digital Signature Algorithm (ECDSA)
         *
         * To generate key pairs for other algorithms:
         * KeyPair keyPair = Jwts.SIG.RS256.keyPair().build();
         * KeyPair keyPair = Jwts.SIG.ES256.keyPair().build();
         */
        KeyPair keypair = Jwts.SIG.PS512.keyPair().build();

        // Print information about the asymmetric key pair
        System.out.println("Private algorithm is : " + keypair.getPrivate().getAlgorithm()); // e.g., "RSA"
        System.out.println("Private format is : " + keypair.getPrivate().getFormat());       // e.g., "PKCS#8"

        System.out.println("Public algorithm is : " + keypair.getPublic().getAlgorithm());   // e.g., "RSA"
        System.out.println("Public format is : " + keypair.getPublic().getFormat());         // e.g., "X.509"

        System.out.println("Secret Key Algorithm: " + key.getAlgorithm()); // Should print "HmacSHA256"
        System.out.println("Secret Key Format   : " + key.getFormat());    // Typically "RAW"

        // ======================================
        // 3. Set JWT Expiration Time
        // ======================================

        long nowMillis = System.currentTimeMillis();         // Current time
        long expMillis = nowMillis + 3600000;                // 1 hour in milliseconds
        Date exp = new Date(expMillis);                      // Expiration date object

        // ======================================
        // 4. Create and Sign JWT using HS256 Key
        // ======================================

        /*
         * Creates a JWT with:
         * - "sub" (subject) claim: identifies the user
         * - Custom "role" claim: indicates user role
         * - "iat" (issued at) and "exp" (expiration) standard claims
         * - Signed using HMAC-SHA256 via the previously generated secret key
         */
        String jws = Jwts.builder()
                .subject("user123")                 // Standard claim: Subject
                .claim("role", "admin")             // Custom claim
                .issuedAt(new Date(nowMillis))      // Standard claim: Issued at
                .expiration(exp)                    // Standard claim: Expiration
                .signWith(key)                      // Sign with HMAC-SHA256 key
                .compact();                         // Finalize and serialize

        // Output the generated JWT string
        System.out.println("Generated JWT: " + jws);

        // ======================================
        // 5. Parse and Validate JWT
        // ======================================

        try {
            /*
             * Parse and validate the signed JWT using the same secret key:
             * - verifyWith(key): Sets the key used to verify the signature.
             * - parseSignedClaims(jws): Parses and verifies the signature.
             * - getPayload(): Retrieves claims from the token.
             */
            Claims claims = Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(jws)
                    .getPayload();

            // Print extracted claims
            System.out.println("Subject: " + claims.getSubject());          // "user123"
            System.out.println("Role: " + claims.get("role"));              // "admin"
            System.out.println("Expiration: " + claims.getExpiration());    // Expiration time

        } catch (JwtException e) {
            /*
             * Exception block handles any issues during parsing or validation:
             * - ExpiredJwtException: Token is expired
             * - MalformedJwtException: Token is not in correct format
             * - SignatureException: Signature is invalid
             */
            System.out.println("Invalid JWT: " + e.getMessage());
        }
    }
}
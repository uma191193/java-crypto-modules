/*
package bc;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.spec.MLDSAParameterSpec;

import java.security.*;
import java.security.spec.*;

public class BC_ML_DSA_V1 {
    public static void main(String[] args) throws Exception {
        // Register Bouncy Castle PQC provider
        Security.addProvider(new BouncyCastleProvider());

        System.out.println("=== ML-DSA (Dilithium) Signature Demo ===");

        // 1. Generate ML-DSA key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BCPQC");
        kpg.initialize(MLDSAParameterSpec.ml_dsa_3); // levels: 2, 3, 5
        KeyPair kp = kpg.generateKeyPair();

        // 2. Sign a message
        String message = "Hello Post-Quantum World!";
        Signature signer = Signature.getInstance("ML-DSA", "BCPQC");
        signer.initSign(kp.getPrivate());
        signer.update(message.getBytes());
        byte[] sig = signer.sign();

        System.out.println("Signature length: " + sig.length);

        // 3. Verify the signature
        Signature verifier = Signature.getInstance("ML-DSA", "BCPQC");
        verifier.initVerify(kp.getPublic());
        verifier.update(message.getBytes());
        boolean ok = verifier.verify(sig);

        System.out.println("Signature verified: " + ok);

        // 4. Demonstrate KeyFactory (reload keys)
        byte[] pubEncoded = kp.getPublic().getEncoded();
        byte[] privEncoded = kp.getPrivate().getEncoded();

        KeyFactory kf = KeyFactory.getInstance("ML-DSA", "BCPQC");
        PublicKey restoredPub = kf.generatePublic(new X509EncodedKeySpec(pubEncoded));
        PrivateKey restoredPriv = kf.generatePrivate(new PKCS8EncodedKeySpec(privEncoded));

        System.out.println("Restored public key algorithm: " + restoredPub.getAlgorithm());
        System.out.println("Restored private key algorithm: " + restoredPriv.getAlgorithm());
    }
}

*/

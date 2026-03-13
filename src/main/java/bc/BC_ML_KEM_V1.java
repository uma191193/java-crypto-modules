/*
package bc;

import org.bouncycastle.jcajce.interfaces.MLKEMPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLKEMPublicKey;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

public class BC_ML_KEM_V1 {
    public static void main(String[] args) throws Exception {
        // Register Bouncy Castle PQC provider, as KEM classes require it
        Security.addProvider(new BouncyCastlePQCProvider());

        System.out.println("=== ML-KEM (Kyber) KEM Demo ===");

        // 1. Generate ML-KEM key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BCPQC");
        kpg.initialize(MLKEMParameterSpec.ml_kem_768); // levels: 512, 768, 1024
        KeyPair kp = kpg.generateKeyPair();

        MLKEMPublicKey pub = (MLKEMPublicKey) kp.getPublic();
        MLKEMPrivateKey priv = (MLKEMPrivateKey) kp.getPrivate();

        // 2. Encapsulation (Alice generates shared secret + encapsulation)
        */
/*KEMGenerator kemGen = new KEMGenerator("ML-KEM", new SecureRandom());
        KEMGenerateSecret kemSecret = kemGen.generateEncapsulated(pub);
        SecretKey aliceShared = kemSecret.getSecret();
        byte[] encapsulation = kemSecret.getEncapsulation();

        System.out.println("Encapsulation length: " + encapsulation.length);

        // 3. Decapsulation (Bob derives the same shared secret)
        KEMExtractor kemExt = new KEMExtractor(priv, "ML-KEM");
        SecretKey bobShared = kemExt.extractSecret(encapsulation);

        boolean match = MessageDigest.isEqual(aliceShared.getEncoded(), bobShared.getEncoded());
        System.out.println("Shared secrets match: " + match);*//*

    }
}
*/

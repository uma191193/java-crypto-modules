/*
package jdk_24;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class PQCParameterInspector_V1 {

    // Known OID mapping for ML-KEM and ML-DSA parameter sets (from NIST FIPS 203/204)
    private static final Map<String, String> OID_MAP = new HashMap<>();

    static {

        // --- NIST OIDs (FIPS 203 / 204 final assignments) ---
        OID_MAP.put("2.16.840.1.101.3.4.4.1", "ML-KEM-512");
        OID_MAP.put("2.16.840.1.101.3.4.4.2", "ML-KEM-768");
        OID_MAP.put("2.16.840.1.101.3.4.4.3", "ML-KEM-1024");

        OID_MAP.put("2.16.840.1.101.3.4.5.1", "ML-DSA-44");
        OID_MAP.put("2.16.840.1.101.3.4.5.2", "ML-DSA-65");
        OID_MAP.put("2.16.840.1.101.3.4.5.3", "ML-DSA-87");

        // --- Legacy CRYSTALS OIDs (for compatibility) ---
        OID_MAP.put("1.3.6.1.4.1.2.267.11.4.3", "ML-KEM-512");
        OID_MAP.put("1.3.6.1.4.1.2.267.11.4.4", "ML-KEM-768");
        OID_MAP.put("1.3.6.1.4.1.2.267.11.4.5", "ML-KEM-1024");

        OID_MAP.put("1.3.6.1.4.1.2.267.7.6.5", "ML-DSA-44");
        OID_MAP.put("1.3.6.1.4.1.2.267.7.6.6", "ML-DSA-65");
        OID_MAP.put("1.3.6.1.4.1.2.267.7.6.7", "ML-DSA-87");
    }


    public static String detectDefaultParam(String familyName) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(familyName);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();

        byte[] encoded = publicKey.getEncoded();
        String oid = extractOID(encoded);

        return OID_MAP.getOrDefault(oid, "Unknown OID: " + oid);
    }

    // Very simple OID extraction: looks for the DER OBJECT IDENTIFIER bytes
    private static String extractOID(byte[] encoded) {
        // Search for OID tag (0x06) and length byte
        for (int i = 0; i < encoded.length - 2; i++) {
            if (encoded[i] == 0x06) {
                int len = encoded[i + 1] & 0xFF;
                byte[] oidBytes = Arrays.copyOfRange(encoded, i + 2, i + 2 + len);
                return decodeOID(oidBytes);
            }
        }
        return "Unknown";
    }

    // Decode DER OID bytes into dotted string
    private static String decodeOID(byte[] oidBytes) {
        StringBuilder oid = new StringBuilder();
        int first = oidBytes[0] & 0xFF;
        oid.append(first / 40).append('.').append(first % 40);

        long value = 0;
        for (int i = 1; i < oidBytes.length; i++) {
            int b = oidBytes[i] & 0xFF;
            value = (value << 7) | (b & 0x7F);
            if ((b & 0x80) == 0) {
                oid.append('.').append(value);
                value = 0;
            }
        }
        return oid.toString();
    }

    // Demo
    public static void main(String[] args) throws Exception {
        System.out.println("Default ML-KEM param: " + detectDefaultParam("ML-KEM"));
        System.out.println("Default ML-DSA param: " + detectDefaultParam("ML-DSA"));
    }
}

*/

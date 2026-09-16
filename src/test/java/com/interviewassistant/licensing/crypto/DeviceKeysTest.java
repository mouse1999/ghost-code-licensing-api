package com.interviewassistant.licensing.crypto;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;

import static org.junit.jupiter.api.Assertions.*;

class DeviceKeysTest {

    private static String sign(KeyPair p, String m) throws Exception {
        Signature s = Signature.getInstance("Ed25519");
        s.initSign(p.getPrivate());
        s.update(m.getBytes(StandardCharsets.UTF_8));
        return Base64Url.encode(s.sign());
    }

    @Test
    void proofOfPossessionVerifiesOnlyForTheMatchingKeyAndExactMessage() throws Exception {
        KeyPair device = PemKeys.generateEd25519();
        KeyPair other = PemKeys.generateEd25519();
        String pub = Base64Url.encode(device.getPublic().getEncoded());
        String msg = DeviceKeys.activateMessage("a@example.com", DeviceKeys.thumbprint(pub), 1000L, "n".repeat(16));
        String sig = sign(device, msg);
        assertTrue(DeviceKeys.verify(DeviceKeys.parsePublicKey(pub), msg, sig));
        assertFalse(DeviceKeys.verify(other.getPublic(), msg, sig), "another device's key");
        assertFalse(DeviceKeys.verify(DeviceKeys.parsePublicKey(pub), msg + "x", sig), "altered message");
        assertFalse(DeviceKeys.verify(DeviceKeys.parsePublicKey(pub), msg, "not-base64!"));
        assertFalse(DeviceKeys.verify(DeviceKeys.parsePublicKey(pub), msg, Base64Url.encode(new byte[10])));
    }

    @Test
    void signatureForOneOperationCannotBeReplayedAsAnother() throws Exception {
        KeyPair device = PemKeys.generateEd25519();
        String validate = DeviceKeys.operationMessage("validate", "L", "D", 5L, "N");
        String entitlement = DeviceKeys.operationMessage("entitlement", "L", "D", 5L, "N");
        String sig = sign(device, validate);
        assertTrue(DeviceKeys.verify(device.getPublic(), validate, sig));
        assertFalse(DeviceKeys.verify(device.getPublic(), entitlement, sig));
    }

    @Test
    void thumbprintIsStableSha256OfTheKeyBytes() {
        String pub = Base64Url.encode(PemKeys.generateEd25519().getPublic().getEncoded());
        assertEquals(DeviceKeys.thumbprint(pub), DeviceKeys.thumbprint(pub));
        assertTrue(DeviceKeys.thumbprint(pub).matches("[0-9a-f]{64}"));
    }

    @Test
    void onlyEd25519SubjectPublicKeyInfoIsAccepted() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> DeviceKeys.parsePublicKey("AAAA"));
        assertThrows(IllegalArgumentException.class, () -> DeviceKeys.parsePublicKey(Base64Url.encode(new byte[44])));
        assertThrows(IllegalArgumentException.class, () -> DeviceKeys.parsePublicKey("has spaces"));
        java.security.KeyPairGenerator rsa = java.security.KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        assertThrows(IllegalArgumentException.class,
                () -> DeviceKeys.parsePublicKey(Base64Url.encode(rsa.generateKeyPair().getPublic().getEncoded())));
    }
}

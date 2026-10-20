package com.interviewassistant.licensing.web;

import com.interviewassistant.licensing.crypto.Base64Url;
import com.interviewassistant.licensing.crypto.SigningKeyRing;
import com.interviewassistant.licensing.service.ClientLicenseService;
import com.interviewassistant.licensing.service.ClientLicenseService.ActivateCommand;
import com.interviewassistant.licensing.service.ClientLicenseService.DeviceRequest;
import com.interviewassistant.licensing.web.Dtos.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Customer / desktop-client API. These endpoints are public (no bearer token): what authorises a call is the activation code
 * plus a device-key signature, checked in {@link ClientLicenseService}.
 */
@RestController
@RequestMapping("/api/v1")
class ClientController {

    private final ClientLicenseService client;
    private final SigningKeyRing keys;

    ClientController(ClientLicenseService client, SigningKeyRing keys) {
        this.client = client;
        this.keys = keys;
    }

    @PostMapping("/client/activate")
    ActivationResponse activate(HttpServletRequest http, @Valid @RequestBody ActivateRequest r) {
        var a = client.activate(new ActivateCommand(r.email(), r.activationCode(), r.devicePublicKey(), r.proofTimestamp(),
                r.proofNonce(), r.proofSignature(), r.deviceLabel(), r.supplementaryFingerprint(), ClientAddress.of(http)));
        return new ActivationResponse(a.licenseId(), a.deviceRegistrationId(), a.status(), a.rights(), a.licenseExpiresAt(),
                a.entitlement(), a.entitlementExpiresAt(), a.renewAfter(), a.alreadyRegistered());
    }

    @PostMapping("/client/validate")
    ValidationResponse validate(HttpServletRequest http, @Valid @RequestBody DeviceProofRequest r) {
        var v = client.validate(device(http, r));
        return new ValidationResponse(true, v.licenseId(), v.deviceRegistrationId(), v.status(), v.rights(), v.licenseExpiresAt(),
                v.serverTime());
    }

    @PostMapping("/client/entitlement")
    EntitlementResponse entitlement(HttpServletRequest http, @Valid @RequestBody DeviceProofRequest r) {
        var e = client.entitlement(device(http, r));
        return new EntitlementResponse(e.licenseId(), e.deviceRegistrationId(), e.rights(), e.licenseExpiresAt(), e.entitlement(),
                e.entitlementExpiresAt(), e.renewAfter());
    }

    /**
     * The PUBLIC verification keys (RFC 8037 JWK, Ed25519), for operations and tooling. The desktop application must embed its
     * trusted keys at build time and must not adopt keys it first sees here (that would let a network attacker choose them).
     */
    @GetMapping("/entitlement-keys")
    Jwks keys() {
        List<Jwk> out = new ArrayList<>();
        for (Map.Entry<String, PublicKey> e : keys.publicKeys().entrySet()) {
            byte[] spki = e.getValue().getEncoded();
            byte[] raw = Arrays.copyOfRange(spki, spki.length - 32, spki.length);
            out.add(new Jwk("OKP", "Ed25519", e.getKey(), Base64Url.encode(raw), "sig", "EdDSA"));
        }
        return new Jwks(out);
    }

    private static DeviceRequest device(HttpServletRequest http, DeviceProofRequest r) {
        return new DeviceRequest(r.licenseId(), r.deviceRegistrationId(), r.proofTimestamp(), r.proofNonce(), r.proofSignature(),
                ClientAddress.of(http));
    }
}

package com.interviewassistant.licensing.crypto;

import java.util.Base64;

/** Unpadded base64url (RFC 4648 section 5), the encoding used by JWS. */
public final class Base64Url {

    private Base64Url() {
    }

    public static String encode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** Strict decode: padding, whitespace and characters outside the url-safe alphabet are rejected. */
    public static byte[] decode(String text) {
        if (text == null) {
            throw new IllegalArgumentException("missing base64url value");
        }
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!ok) {
                throw new IllegalArgumentException("not base64url");
            }
        }
        try {
            return Base64.getUrlDecoder().decode(text);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("not base64url");
        }
    }
}

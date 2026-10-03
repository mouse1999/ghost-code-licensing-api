package com.interviewassistant.licensing.service;

import java.util.Locale;
import java.util.regex.Pattern;

/** E-mail normalisation: one canonical form is stored and compared (trimmed, lower-case). */
public final class Emails {

    private static final Pattern SHAPE = Pattern.compile("[^@\\s]{1,64}@[^@\\s]{1,189}\\.[^@\\s.]{2,63}");

    private Emails() {
    }

    /** @throws LicensingException VALIDATION_FAILED if the value is not a plausible e-mail address */
    public static String normalize(String email) {
        if (email == null) {
            throw new LicensingException(ErrorCode.VALIDATION_FAILED, "email is required");
        }
        String e = email.trim().toLowerCase(Locale.ROOT);
        if (e.length() > 254 || !SHAPE.matcher(e).matches()) {
            throw new LicensingException(ErrorCode.VALIDATION_FAILED, "email is not valid");
        }
        return e;
    }
}

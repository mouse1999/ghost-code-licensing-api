package com.interviewassistant.licensing.domain;

/**
 * A right a license can grant. The names match the desktop application's feature modes so that the later enforcement phase
 * can map them one-to-one. The server decides which rights a license carries; the desktop never does.
 */
public enum LicenseRight {
    LIVE,
    AI_LIVE,
    DSA,
    SCREEN_QUESTION
}

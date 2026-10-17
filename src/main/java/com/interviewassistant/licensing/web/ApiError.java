package com.interviewassistant.licensing.web;

/** The one error body every endpoint returns: a stable {@code code} and a safe, generic {@code message}. */
public record ApiError(String code, String message) {
}

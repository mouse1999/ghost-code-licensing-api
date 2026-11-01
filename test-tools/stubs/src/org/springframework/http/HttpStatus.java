package org.springframework.http; public enum HttpStatus { OK(200), CREATED(201); public final int code; HttpStatus(int c){code=c;} }

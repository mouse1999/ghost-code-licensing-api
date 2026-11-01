package org.springframework.http;
public class ResponseEntity<T> { final int status; final T body; ResponseEntity(int s, T b){status=s;body=b;} public int statusCode(){return status;} public T body(){return body;}
 public static BodyBuilder status(HttpStatus s){return new BodyBuilder(s.code);} public static BodyBuilder ok(){return new BodyBuilder(200);}
 public static class BodyBuilder { final int s; BodyBuilder(int s){this.s=s;} public BodyBuilder contentType(MediaType m){return this;} public <T> ResponseEntity<T> body(T b){return new ResponseEntity<>(s,b);} } }

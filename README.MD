A simple Java JWT library

### Creating a new JWT Token

###### With a custom payload object
```java
String secret = "a secret";
APayload payload = new APayload();

JWTToken token = new JWTToken(payload, secret);
String encoded = token.toString();
```

###### With an expiry
```java
String secret = "a secret";
APayload payload = new APayload();

long expiry = System.currentTimeMillis() + 60000;
JWTBody body = new JWTBody(expiry, payload);
JWTToken token = new JWTToken(body, secret);
String encoded = token.toString();
```

### Decoding

```java
String jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjF9.8onrqJhmsoas7S-2eOXSmQe1UZfbsK0zZyIw7ik8gZE";
JWTToken token = JWTToken.from(jwt);
APayload payload = token.getBody().getPayload(APayload.class); // Uses Jackson to deserialize
```

### Validating
```java
String jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjF9.8onrqJhmsoas7S-2eOXSmQe1UZfbsK0zZyIw7ik8gZE";
JWTToken token = JWTToken.from(jwt);
boolean isValid = token.isValid("a secret"); // Verifies the token is valid and not expired
```


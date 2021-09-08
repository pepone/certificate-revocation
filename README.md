This sample ilustrate that the CRL distribution point is not contacted by `SecTrustEvaluateWithError`

# Compilation

```
clang++ main.cpp -o revocation -framework Security -framework CoreFoundation
```

# Run

Start a HTTP server from this directory to ensure the CRL is available at the distribution point

```
python -m SimpleHTTPServer 20001
```

Run the test executable

```
./revocation
```

# Expected Result

Verificaction should contact the CRL distribution point and trust error should indicate that
the certificate has been revoked, `errSecCertificateRevoked` the program should output
`not trusted: certificate revoked`

# Actual Result

The certificate is not trusted, the trust error indicate the revocation check was not complete
`errSecIncompleteCertRevocationCheck` the program outputs `not trusted: incomplete revocation check`

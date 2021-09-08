This sample ilustrate that the CRL distribution point is not contacted by `SecTrustEvaluateWithError`

# Compilation

clang++ main.cpp -o revocation -framework Security -framework CoreFoundation

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

The certificate must be trusted, and the program should output `trusted`

# Actual Result

The certificate is not trusted, and the program outputs `not trusted error code: -67635`
this correspond with `errSecIncompleteCertRevocationCheck` error

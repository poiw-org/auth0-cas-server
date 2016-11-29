# Files for RS256 tests

Some of the tests use id_tokens that have been signed using the RS256 algorithm, which uses a private key for signature and a public key for validation. The files required to perform those tests are in this folder.

They are:
* `private.key`: the private key file
* `public.crt`: a self-signed certificate that contains the public key

These files were generated using this command:

```sh
openssl req -nodes -new -x509 -keyout private.key -out public.crt -subj "/C=US/ST=Washington/L=Bellevue/O=Auth0/CN=Auth0 Samples"
```

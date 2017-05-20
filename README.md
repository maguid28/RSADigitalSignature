# RSADigitalSignature

This is my implementation of a digital signature using RSA.

The public/private RSA key pair are set up as follows:

Generate two distinct 512-bit probable primes p and q
Calculate the product of these two primes N = pq
Calculate the Euler totient function phi(N)
Encryption exponent is e = 65537, which is relatively prime to phi(N).
The decryption exponent d is the multiplicative inverse of e (mod phi(N)). This makes use of the extended Euclidean GCD algorithm to calculate the inverse rather than using a built in library method.

The decryption method calculates c^d (mod N) and uses my own implementation of the chinese remainder theorem to calculate it more effeciently.

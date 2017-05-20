/*
Author: Daniel Maguire

This is my implementation of a digital signature using RSA.
*/

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Random;
import java.util.Scanner;

public class RSADigitalSignature {

    //Calculate GCD of two numbers
    private static BigInteger myGCD(BigInteger a, BigInteger b) {

        while (b.compareTo(BigInteger.ZERO) > 0) {
            BigInteger temp = b;
            b = a.mod(b);
            a = temp;
        }
        return a;
    }

    //Modular Multiplicative inverse
    private static BigInteger myMultInverse(BigInteger base, BigInteger mod){

        BigInteger[] ans = EEAlgorithm(base,mod);
        if((ans[0]).compareTo(BigInteger.ZERO) > 0) {
            return ans[0];
        }
        else return ans[0].add(mod);
    }

    //Extended Eucledian Algorithm
    private static BigInteger[] EEAlgorithm(BigInteger a, BigInteger b) {

        BigInteger[] ans = new BigInteger[2];
        BigInteger q;

        if (b.equals(BigInteger.ZERO)){
            ans[0] = BigInteger.ONE;
            ans[1] = BigInteger.ZERO;
        }
        else {
            q = a.divide(b);
            BigInteger aModb = a.mod(b);
            ans = EEAlgorithm (b, aModb);
            BigInteger temp = ans[0].subtract(ans[1].multiply(q));
            ans[0] = ans[1];
            ans[1] = temp;
        }
        return ans;
    }

    //decryption method using chinese remainder theorem
    private static BigInteger decrypt(BigInteger d, BigInteger p, BigInteger q, BigInteger m){

        BigInteger dP, dQ, qInv, m1, m2, h;

        //dP = d mod (p-1)
        dP = d.mod(p.subtract(BigInteger.ONE));
        //dQ = d mod (q-1)
        dQ = d.mod(q.subtract(BigInteger.ONE));
        //qInv = q^-1 mod p
        qInv = myMultInverse(q,p);
        //m1 = c^dP mod p
        m1 = m.modPow(dP,p);
        //m2 = c^dQ mod q
        m2 = m.modPow(dQ,q);
        //h = qInv.(m1 - m2) mod p
        h = qInv.multiply(m1.subtract(m2)).mod(p);
        //m = m2 + h.q
        m = m2.add(h.multiply(q));

        return m;
    }


    private static byte[] readBinaryFile(String aFileName) throws IOException {

        Path filepath = Paths.get(aFileName);
        return Files.readAllBytes(filepath);
    }

    //Generate a 256-bit digest of the zip file
    private static byte[] SHA256Digest(byte[] inputBytes) {

        byte[] digestedBytes = new byte[0];
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(inputBytes);
            digestedBytes = messageDigest.digest();
        } catch (Exception ignored) {}

        return digestedBytes;
    }



    public static void main(String[] args) {

        BigInteger n = BigInteger.ZERO;
        BigInteger e = new BigInteger("65537");
        BigInteger d;
        BigInteger p = BigInteger.ZERO;
        BigInteger q = BigInteger.ZERO;
        BigInteger gcd = new BigInteger("0");
        BigInteger phiN = new BigInteger("0");

        while(!(gcd.equals(BigInteger.ONE))) {
            //Generate two distinct 512-bit probable primes p and q
            Random rnd = new Random();
            p = BigInteger.probablePrime(512, rnd);
            q = BigInteger.probablePrime(512, rnd);

            //product of these two primes N = pq
            n = p.multiply(q);

            //Euler totient function phi(N) = (p-1)(q-1)
            phiN = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

            //Find the GCD of e and phi(N)
            gcd = myGCD(e, phiN);
        }

        //multiplicative inverse of e (mod phi(N)
        d = myMultInverse(e, phiN);

        Scanner scanner = new Scanner(System.in);
        System.out.println("Input full path of file to generate signature: ");
        String input_file = scanner.nextLine();

        try{
            byte[] bytes = readBinaryFile(input_file);

            //256 bit digest of the file using SHA-256
            byte[] digestOfFile = SHA256Digest(bytes);
            BigInteger message = new BigInteger(digestOfFile);

            //Apply decryption method to digest
            BigInteger digitalSignature = decrypt(d,p,q,message);

            System.out.println("Public Modulus N:      \n" + n.toString(16));
            System.out.println("256-bit digest:        \n" + message.toString(16));
            System.out.println("RSA Digital Signature: \n"+ digitalSignature.toString(16));
        } catch (IOException e1) {
            e1.printStackTrace();
        }
    }
}

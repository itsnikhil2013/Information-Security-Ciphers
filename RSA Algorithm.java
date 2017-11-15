import java.math.*;
import java.security.SecureRandom;

/**
 *
 * @author Professional Cipher[www.professionalcipher.blogspot.com]
 */
public class RSA {
    
    private static BigInteger one=new BigInteger("1");
    private static BigInteger n;
    private static BigInteger phi;
    private static BigInteger e;
    private static BigInteger d;
    
    public RSA()
    {
        BigInteger p=BigInteger.probablePrime(40, new SecureRandom());
        BigInteger q=BigInteger.probablePrime(40, new SecureRandom());
        
        n=p.multiply(q);
        phi=(p.subtract(one)).multiply(q.subtract(one));
        e=new BigInteger("65537"); //only use prime number
        d=e.modInverse(phi);
    }
    
    public BigInteger encrypt(BigInteger msg)
    {
        return msg.modPow(e, n);
    }
    
    public BigInteger decrypt(BigInteger msg)
    {
        return msg.modPow(d, n);
    }

    @Override
    public String toString() {
        return "Public key="+e.longValue()+"\nPrivate key="+d.longValue()+"\nModuli="+n.longValue();
    }
   
    public static void main(String[] args) {
        RSA rsa=new RSA();
        System.out.println(rsa);
        String msg="BEIT";
        System.out.println("Plaintext="+msg);
        BigInteger plaintext=new BigInteger(msg.getBytes()); 
        BigInteger ciphertext=rsa.encrypt(plaintext); 
        System.out.println("Encrypted message="+new String(ciphertext.toByteArray()));
        BigInteger dplaintext=rsa.decrypt(ciphertext); 
        System.out.println("Decrypted message="+new String(dplaintext.toByteArray()));
    }
    
}
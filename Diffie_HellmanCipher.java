import java.io.*;
import java.math.BigInteger;

/*
 * 
 *  @ author Professional Cipher [www.professionalcipher.com]
 * 
 */

public class Diffie_Hellman {
 
 public static void main(String[]args)throws IOException
    {
        BufferedReader br=new BufferedReader(new InputStreamReader(System.in));
        System.out.print("Enter prime number :  ");
        BigInteger p=new BigInteger(br.readLine());
        System.out.print("Enter primitive root of "+p+" :  ");
        BigInteger g=new BigInteger(br.readLine());
        System.out.print("Enter value for x less than "+p+" :  ");
        BigInteger x=new BigInteger(br.readLine());
        BigInteger R1=g.modPow(x,p);
        System.out.println("R1  =  "+R1);
        System.out.print("Enter value for y less than "+p+" :  ");
        BigInteger y=new BigInteger(br.readLine());
        BigInteger R2=g.modPow(y,p);
        System.out.println("R2  =  "+R2);
        BigInteger k1=R2.modPow(x,p);
        System.out.println("Key calculated at Alice's side :  "+k1);
        BigInteger k2=R1.modPow(y,p);
        System.out.println("Key calculated at Bob's side :  "+k2);
        System.out.println("Deffie Hellman Secret Key Encryption has Taken!");
    }

}
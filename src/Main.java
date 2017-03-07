import java.io.*;
import java.security.*;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import org.json.*;


public class Main {
	
	public static void main(String args[]) throws ClassNotFoundException, IOException{
		
		final String PRIVATE_KEY = "C:/Users/Ryan/Desktop/private_key.pem";
		final String PUBLIC_KEY = "C:/Users/Ryan/Desktop/public_key - Copy.pem";
	
		/*Scanner scan = new Scanner(new File(PUBLIC_KEY));
		scan.nextLine();
		while(scan.hasNext()){
			System.out.println(scan.next());
		}*/
		
		/*ObjectInputStream input = new ObjectInputStream(new FileInputStream(new File(PUBLIC_KEY)));
		PublicKey pubkey = (PublicKey) input.readObject();*/
		
		
		System.out.println("Enter message: ");
		Scanner in = new Scanner(System.in);
		//String message = scan.nextLine();
		
		//JSONObject json = encrypt(message, );
	}
	
	private static JSONObject encrypt(String message, PublicKey pubKey){
		JSONObject json = new JSONObject();
		byte[] AESciphertext = null;
		byte[] HMACtag = null;
		SecretKey AESkey = null;
		SecretKeySpec HMACkey = null;
		
		// generate AES key
		try
		{
			KeyGenerator AESKeyGen = KeyGenerator.getInstance("AES");
			AESKeyGen.init(256);
			AESkey = AESKeyGen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Error with AES.");
		}
		
		// encrypt message with AES + IV
		try{
			Cipher aes = Cipher.getInstance("AES");
			aes.init(Cipher.ENCRYPT_MODE, AESkey);
			AESciphertext = aes.doFinal(message.getBytes());
		} catch (Exception e){
			e.printStackTrace();
		}
		
		
		//generate HMAC key
		final int HMACkeysize = 32;

		SecureRandom RNG = new SecureRandom();
		byte[] random = new byte[HMACkeysize];
		RNG.nextBytes(random);
		
		
		// SHA 256 ciphertext for integrity tag
		
		
		// encrypt AES key + HMAC key with RSA
		try{
			Cipher rsa = Cipher.getInstance("RSA");
			rsa.init(Cipher.ENCRYPT_MODE, pubKey);
			byte[] ciphertext = rsa.doFinal(AESkey.getEncoded() + HMACkey.getEncoded());
		} catch (Exception e){
			e.printStackTrace();
		}
		
		// output RSA ciphertext, AES ciphertext, and HMAC tag in JSON
		return json;
	}
	
	private static String decrypt(byte[] ciphertext){
		
		
		
	}

}

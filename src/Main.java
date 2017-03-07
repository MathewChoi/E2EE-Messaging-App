import java.security.*;
import javax.crypto.*;


public class Main {
	
	public static void Main(String args[]){
		
		final String PRIVATE_KEY = "C:/Users/Ryan/Desktop/private_key.pem";
		final String PUBLIC_KEY = "C:/Users/Ryan/Desktop/public_key.pem";
	}
	
	private static byte[] encrypt(String message, PublicKey pubKey){
		byte[] cipherText = null;
		
		try{
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			cipherText = cipher.doFinal(message.getBytes());
		} catch (Exception e){
			e.printStackTrace();
		}
		
		try{
			Cipher cipher = Cipher.getInstance("HMAC")
		}
		
		return cipherText;
	}
	
	private static String decrypt(){
		
	}

}

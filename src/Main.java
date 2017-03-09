import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Scanner;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.json.*;

/**
 * 
 * MATHEW READ THIS
 * 
 * I couldn't figure out how to read in the private key. 
 * I tried converting the .pem files to .der and using the code
 * from github like the other group but that wasn't working.
 * 
 * I ended up just adding comments and trying to clean up the code
 * and we can talk to Dad about the issue.
 * 
 * Also we should probably create Encrypter and Decrypter classes
 * because having one huge class is getting messy.
 *
 */
public class TestDriver
{
	final private static String PUBLIC_KEY_PATH = "C:\\Users\\Mathew Choi\\Desktop\\public_key.pem";
	final private static String PRIVATE_KEY_PATH = "C:\\Users\\Mathew Choi\\Desktop\\private_key.pem";
	final private static String plaintext = "Security is not an afterthought; it starts with design.";
	final private static int AES_KEYLENGTH = 256;

	public static void main(String[] args)
	{
		RSAPublicKey rsaPublicKey = getPublicKey(PUBLIC_KEY_PATH);
		try
		{
			// get JSON object with encrypted information
			JSONObject ciphertextJSON = encrypt(plaintext, rsaPublicKey);

			// print JSON object
			System.out.println(ciphertextJSON.toString());

			// decrypt JSON object
			String plaintext = decrypt(ciphertextJSON);
		}
		catch (InvalidKeyException | NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		}
	}

	// --------------------------------------------------------------------------------
	// ENCRYPT methods
	// --------------------------------------------------------------------------------

	/**
	 * Encrypts the message and keys and stores them in a JSON object.
	 * 
	 * @param plaintext - The message to be encrypted.
	 * @param key -  the RSA public key that will be used to encrypt the AES + HMAC key
	 * @return The JSON object with all the stuff we need to decrypt/verify later.
	 */
	private static JSONObject encrypt(String plaintext, RSAPublicKey key)
			throws NoSuchAlgorithmException, InvalidKeyException
	{
		// get AES key
		SecretKey AESkey = generateAESKey();
		System.out.println("AESkey.length = " + AESkey.getEncoded().length);

		// encrypt plaintext with AES key and 16-bit IV
		IvParameterSpec IV = getIV();

		byte[] ciphertext = AESEncrypt(plaintext, AESkey, IV);

		// generate HMACSHA256 key
		SecretKeySpec HMACkey = generateHMACKey();

		// generate HMAC tag
		byte[] HMACtag = generateHMACtag(ciphertext, HMACkey);

		// concatenate HMACkey and AESkey
		byte[] encodedAESkey = AESkey.getEncoded();
		byte[] encodedHMACkey = HMACkey.getEncoded();
		byte[] AESHMACkey = concatAESHMACkeys(encodedAESkey, encodedHMACkey);

		// RSA encrypt AESkey + HMACkey
		byte[] RSAencrypted = RSAencrypt(AESHMACkey, key);

		// return the RSA ciphertext, AES ciphertext, and HMAC tag in a JSON
		// object
		JSONObject encrJSON = new JSONObject();
		try
		{	//since we didn't encode the data into the JSON object, I suspect that we're going to have issues reading in its contents.
			encrJSON.put("ConcatKeys", RSAencrypted);
			encrJSON.put("IV", IV);
			encrJSON.put("Ciphertext", ciphertext);
			encrJSON.put("HMACtag", HMACtag);
		}
		catch (JSONException e)
		{
			e.printStackTrace();
		}
		System.out.println("Done with encryption");
		return encrJSON;
	}

	/**
	 * Gets the RSA public key from a file.
	 * 
	 * @param keyPath - The path to the file with the key.
	 * @return The RSAPublicKey object to be used for encrypting.
	 */
	private static RSAPublicKey getPublicKey(String keyPath)
	{
		File pemFile = new File(keyPath.toString());
		Scanner in;
		StringBuilder key = new StringBuilder();
		RSAPublicKey rsaPublicKey = null;
		try
		{
			// read the contents of the pem into a string
			in = new Scanner(pemFile);
			while (in.hasNextLine())
			{
				String line = in.nextLine();
				key.append(line);
				key.append("\n");
			}
			in.close();
			String pemKey = key.toString();

			System.out.println("pem file = ");
			System.out.print(pemKey);

			// use BouncyCastle's PEMReader to convert to and RSAkey
			Security.addProvider(new BouncyCastleProvider());
			PEMReader pemReader = new PEMReader(new StringReader(pemKey));

			rsaPublicKey = (RSAPublicKey) pemReader.readObject();
			System.out.println("Public key: " + rsaPublicKey.toString());

			pemReader.close();
		}
		catch (IOException e)
		{
			System.out.println(keyPath.toString() + " not found.");
		}
		return rsaPublicKey;
	}

	/**
	 * Randomly generated an IV for AES encryption.
	 * 
	 * @return The IV generated.
	 */
	private static IvParameterSpec getIV()
	{
		// generate the IVs
		SecureRandom RNG = new SecureRandom();
		byte[] random = new byte[16];
		RNG.nextBytes(random);
		IvParameterSpec IV = new IvParameterSpec(random);
		return IV;
	}

	/**
	 * Generates a key for AES encryption.
	 * 
	 * @return The key generated.
	 */
	private static SecretKey generateAESKey()
	{
		SecretKey aesKey = null;
		try
		{
			KeyGenerator AESKeyGen = KeyGenerator.getInstance("AES");
			AESKeyGen.init(AES_KEYLENGTH);
			aesKey = AESKeyGen.generateKey();
		}
		catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		}
		return aesKey;
	}

	/**
	 * AES encrypts the message based on the AES key and IV.
	 * 
	 * @param plaintext
	 * @param key
	 * @param IV
	 * @return The ciphertext for the message.
	 */
	private static byte[] AESEncrypt(String plaintext, SecretKey key, IvParameterSpec IV)
	{
		byte[] AESEncrypted = null;
		final int blocksize = 16;
		try
		{
			// instantiate AES Cipher
			Cipher AES = Cipher.getInstance("AES/CBC/PKCS7Padding");
			AES.init(Cipher.ENCRYPT_MODE, key, IV);
			AESEncrypted = AES.doFinal(plaintext.getBytes());
		}
		catch (InvalidKeyException | InvalidAlgorithmParameterException
				| IllegalBlockSizeException | BadPaddingException
				| NoSuchAlgorithmException | NoSuchPaddingException e)
		{
			System.out.println("InvalidKeyException in AESEncrypt");
			e.printStackTrace();
		}
		return AESEncrypted;
	}

	/**
	 * Randomly generates an HMAC key with size 32 bits.
	 * 
	 * @return The HMAC key generated.
	 */
	private static SecretKeySpec generateHMACKey()
	{
		final int HMACkeysize = 32;

		// generate 32b random value
		SecureRandom RNG = new SecureRandom();
		byte[] random = new byte[HMACkeysize];
		RNG.nextBytes(random);

		// generate HMAC key
		SecretKeySpec HMACkey = new SecretKeySpec(random, "HMACSHA256");

		return HMACkey;
	}

	/**
	 * Generates a tag based on the ciphertext and HMAC key.
	 * 
	 * @param ciphertext - The ciphertext of the message being sent.
	 * @param keyspec - The HMAC key
	 * @return The tag to be used for verification.
	 */
	private static byte[] generateHMACtag(byte[] ciphertext, SecretKeySpec keyspec)
	{
		Mac HMAC = null;
		try
		{
			HMAC = Mac.getInstance("HMACSHA256");
			HMAC.init(keyspec);
		}
		catch (InvalidKeyException | NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		}

		byte[] returnArr = HMAC.doFinal(ciphertext);
		return returnArr;
	}

	/**
	 * Concatenates the AES and HMAC keys into one byte[] to be RSA encrypted.
	 * 
	 * @param encodedAESkey - byte[] for AES key
	 * @param encodedHMACkey - byte[] for HMAC key
	 * @return A single byte[] from the two keys.
	 */
	private static byte[] concatAESHMACkeys(byte[] encodedAESkey, byte[] encodedHMACkey)
	{
		byte[] AESHMACkey = new byte[encodedAESkey.length + encodedHMACkey.length];
		System.arraycopy(encodedAESkey, 0, AESHMACkey, 0, encodedAESkey.length);
		System.arraycopy(encodedHMACkey, 0, AESHMACkey, encodedAESkey.length, encodedHMACkey.length);
		return AESHMACkey;
	}

	/**
	 * Encrypts the concatenated AES and HMAC keys.
	 * 
	 * @param concatKey - A byte[] of the concatenated keys.
	 * @param RSAkey - The public key to encrypt with.
	 * @return The encrypted byte[].
	 */
	private static byte[] RSAencrypt(byte[] concatKey, RSAPublicKey RSAkey)
	{
		byte[] RSAencrypted = null;
		try
		{
			Cipher RSA = Cipher.getInstance("RSA");
			RSA.init(Cipher.ENCRYPT_MODE, RSAkey);
			RSAencrypted = RSA.doFinal(concatKey);
		}
		catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException e)
		{
			e.printStackTrace();
		}
		return RSAencrypted;
	}

	// --------------------------------------------------------------------------------
	// DECRYPT methods
	// --------------------------------------------------------------------------------

	private static String decrypt(JSONObject ciphertextJSON)
	{
		String plaintext = null;

		// get RSA key
		PrivateKey RSAPrivKey = getPrivateKey(PRIVATE_KEY_PATH);	// should be type RSAPrivateKey

		// decrypt RSA

		// get HMAC key

		// get tag
		
		// check tag

		// get AES key

		// get AES message

		// return message

		return plaintext;
	}

	public static PrivateKey getPrivateKey(String keyPath)	// should ideally return type RSAPrivateKey
	{
		PrivateKey key = null;
		File pemFile = new File(keyPath.toString());
		Scanner in;
		StringBuilder keystr = new StringBuilder();
		RSAPublicKey rsaPublicKey = null;
		try
		{
			// read the contents of the pem into a string
			in = new Scanner(pemFile);
			while (in.hasNextLine())
			{
				String line = in.nextLine();
				keystr.append(line);
				keystr.append("\n");
			}
			in.close();

			String pemKey = keystr.toString();
			byte[] keyBytes = pemKey.getBytes();

			try
			{
				// keyBytes = Files.readAllBytes(new File(keyPath).toPath());
				PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
				KeyFactory kf = KeyFactory.getInstance("RSA");
				key = kf.generatePrivate(spec);
			}
			catch (NoSuchAlgorithmException | InvalidKeySpecException e)
			{
				e.printStackTrace();
			}
		}
		catch (FileNotFoundException e)
		{
			System.out.println(keyPath + " not found.");
		}
		return key;
	}

	/**
	 * Decrypts the concatenated AES and HMAC keys.
	 * 
	 * @param RSAencrypted - the concatenated, encrypted keys
	 * @param privateKey - the key for decryption
	 * @return The decrypted byte[].
	 */
	private static byte[] RSAdecrypt(byte[] RSAencrypted, RSAPrivateKey privateKey)
	{
		byte[] RSAdecrypted = null;

		try
		{
			Cipher RSA = Cipher.getInstance("RSA");
			RSA.init(Cipher.DECRYPT_MODE, privateKey);
			RSAdecrypted = RSA.doFinal(RSAencrypted);
		}
		catch (NoSuchAlgorithmException | NoSuchPaddingException
				| IllegalBlockSizeException | BadPaddingException
				| InvalidKeyException e)
		{
			e.printStackTrace();
		}
		
		return RSAdecrypted;
	}
}
// Java program to demonstrate the creation
// of Encryption and Decryption with Java AES
//import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

class AES {
	// Class private variables
	private static final String SECRET_KEY = "thisKeyIsForTesting434";
    //my_super_secret_key_ho_ho_ho
	
	private static final String SALT = "saltyaboutcs";

	// This method use to encrypt to string
	public static byte[] encrypt(byte[] plaintextToEncrypt) {
		try {

			// make bye array and ivspec
			byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			IvParameterSpec ivspec = new IvParameterSpec(iv);

			// make the secret key factory 
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			// help generate key information 
			KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, 256);
			SecretKey secret = factory.generateSecret(spec);
			// make key 
			SecretKeySpec secretKey = new SecretKeySpec(secret.getEncoded(), "AES");

			// create AES cipher
			Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
			aes.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
			// encrypt plaintext and return string version of encoded string
			return aes.doFinal(plaintextToEncrypt);
		}
		catch (Exception e) {
			return null;
		}
	}

	// This method use to decrypt to string
	public static byte[] decrypt(byte[] ciphertextToDecrypt) {
		try {

			// make bye array and ivspec
			byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			IvParameterSpec ivspec = new IvParameterSpec(iv);

			// make the secret key factory 
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			// help generate key information 
			KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, 256);
			SecretKey secret = factory.generateSecret(spec);
			// make key 
			SecretKeySpec secretKey = new SecretKeySpec(secret.getEncoded(), "AES");

			// create AES cipher
			Cipher aes = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			aes.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
			// decrypt ciphertext and return string version of unencrypted string
			return aes.doFinal(ciphertextToDecrypt);
		}
		catch (Exception e) {
			return null;
		}
	}
	public static void test(String testing){
		byte[] byteArr= testing.getBytes();
		byte[] encryptedArr = AES.encrypt(byteArr);
		byte[] decryptedArr = AES.decrypt(encryptedArr);

		System.out.println(Base64.getEncoder().encodeToString(byteArr));
		System.out.println(Base64.getEncoder().encodeToString(encryptedArr));
		System.out.println(Base64.getEncoder().encodeToString(decryptedArr));

		System.out.println("Number of bytes in testing: " + Integer.toString(byteArr.length));
		System.out.println("Number of bytes in encrypted: " + Integer.toString(encryptedArr.length));
	}
}

class Main {
	public static void main(String[] args) {
		
		AES.test("Testing a much bigger string than others");
		AES.test("t");
		AES.test("Kelly and Ken");

	}
}

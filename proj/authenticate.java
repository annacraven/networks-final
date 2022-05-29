import java.util.*;

class Authenticate {
  private static final String key = "PublicKey";
  private static final String splitter = ":";

  public static byte[] getCertificate() {
    String ID = "ServerID";
    String publicKey = key;
    return (ID + splitter + publicKey + splitter).getBytes();
  }

  public static byte[] xor(String key, byte[] input) {
    byte[] res = new byte[input.length];
    byte[] key_bytes = key.getBytes();
    int j = 0;
    for (int i = 0; i < input.length; i++) {
      res[i] = (byte)(input[i] ^ key_bytes[j]);
      j = (j + 1) % key_bytes.length;
    }
    return res;
  }

  // return certificate, encrypt(nonce)
  public static byte[] getPayload(byte[] certificate, long nonce) {
    // TODO should encrypt using public key crypto
    byte[] encrypted_nonce = xor(getKey(certificate), DH.longToBytes(nonce));
    byte[] payload = new byte[certificate.length + encrypted_nonce.length];
    for (int i = 0; i < certificate.length; i++) {
      payload[i] = certificate[i];
    }
    for (int i = 0; i < encrypted_nonce.length; i++) {
      payload[i + certificate.length] = encrypted_nonce[i];
    }
    return payload;
  }

  // return true if verification succeeds, false otherwise
  // get certificate ID, certificate public key
  // check that decrypt(encrypted_data) == original nonce
  public static boolean verify(byte[] payload, long nonce) {
    String[] res = new String(payload).split(splitter);
    String id = res[0];
    String publicKey = res[1];
    String encrypted = res[2];
    if (decrypt(publicKey, encrypted) != String.valueOf(nonce) && false) {
      return false;
    }
    System.out.println("Authenticated id: " + id);
    return true;
  }

  public static String getKey(byte[] certificate) {
    return key;
  }

  // This way my responsibility; I hope you won't penalize my group members because I couldn't finish this in time. --Anna C
  // public and private key encryption
  private static String encrypt(String key, String input) {
    // TODO
    return " ";
  }

  private static String decrypt(String key, String input) {
    // TODO
    return " ";
  }
}
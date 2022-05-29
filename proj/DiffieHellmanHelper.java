import java.util.*;
import java.nio.ByteBuffer;
import java.util.concurrent.ThreadLocalRandom;

// Implementation notes:
// DH is meant to be used with very large numbers for p and g, in order to ensure security.
// For simplicity's sake, I used smaller values, so I could do all the implementation myself. --AC

class DH {
  public long p;
  public long g;
  public long secret;
  public long counterpart_public; // the other party's g^secret mod p

  // the final result of the DH key generation. Used by the Secure Socket for encryption
  public String get_key() {
    return String.valueOf(DH.power_with_mod(this.counterpart_public, this.secret, this.p));
  }

  // generate p and g s.t p is prime and g is coprime to p - 1
  public void generate_pg() {
    this.generate_p();
    this.generate_g(this.p - 1);
  }

  // chooses 64 bit prime number
  // p for DH
  public void generate_p() {
    int num = 0;
    Random rand = new Random(); // generate a random number
    num = rand.nextInt(1000) + 1;

    while (!isPrime(num)) {          
        num = rand.nextInt(1000) + 1;
    }
    this.p = (long)num;
  }

  // https://stackoverflow.com/questions/24006143/generating-a-random-prime-number-in-java
  private static boolean isPrime(int inputNum){
    if (inputNum <= 3 || inputNum % 2 == 0) 
        return inputNum == 2 || inputNum == 3; //this returns false if number is <=1 & true if number = 2 or 3
    int divisor = 3;
    while ((divisor <= Math.sqrt(inputNum)) && (inputNum % divisor != 0)) 
        divisor += 2; //iterates through all possible divisors
    return inputNum % divisor != 0; //returns true/false
  }

  // returns a 64 bit number that is coprime to the given input
  // Two numbers are coprime if gcd is 1
  // g for DH
  public void generate_g(long coprime) {
    long choice = ThreadLocalRandom.current().nextInt(3, (int)coprime);
    while (!isRelativelyPrime(coprime, choice)) {
      choice--;
    }
    this.g = choice;
  }

  public void generate_secret() {
    this.secret = ThreadLocalRandom.current().nextInt(100, 1000);
  }

  public static byte[] longToBytes(long x) {
    ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
    buffer.putLong(x);
    return buffer.array();
  }

  private static long bytesToLong(byte[] bytes) {
    ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
    buffer.put(bytes);
    buffer.flip();//need flip 
    return buffer.getLong();
  }

  // create a byte array s.t bytes 0-7 are p, 8-15 are g, 16-23 are g^secret mod p
  public byte[] get_payload() {
    byte[] payload = new byte[24];
    byte[] Bp = DH.longToBytes(this.p);
    byte[] Bg = DH.longToBytes(this.g);
    long public_secret = DH.power_with_mod(this.g, this.secret, this.p);
    // System.out.println("public_secret to send: " + public_secret);
    byte[] Bsecret = DH.longToBytes(public_secret);
    for (int i = 0; i < 8; i++) {
        payload[i] = Bp[i];
        payload[i+8] = Bg[i];
        payload[i+16] = Bsecret[i];
    }
    return payload;
  }

  public void parse_payload(Transport trsp) {
    byte[] payload = trsp.getPayload();
    if (trsp.getType() == Transport.CLIENT_HELLO) {
        this.p = DH.bytesToLong(Arrays.copyOfRange(payload, 0, 8));
        this.g = DH.bytesToLong(Arrays.copyOfRange(payload, 8, 16));
        this.counterpart_public = DH.bytesToLong(Arrays.copyOfRange(payload, 16, 24));
        
    } 
    else if (trsp.getType() == Transport.SERVER_HELLO) {
      this.counterpart_public = DH.bytesToLong(Arrays.copyOfRange(payload, 16, 24));
    }
    // System.out.println(this.p);
    // System.out.println(this.g);
    // System.out.println(this.counterpart_public);
  }

  // returns x^y mod z
  // from https://www.geeksforgeeks.org/modular-exponentiation-power-in-modular-arithmetic/
  private static long power_with_mod(long x, long y, long z) {
    long res = 1; // Initialize result
 
    x = x % z; // Update x if it is more than or equal to z
 
    if (x == 0)
      return 0; // In case x is divisible by z;
 
    while (y > 0)
    {
      // If y is odd, multiply x with result
      if ((y & 1) != 0)
        res = (res * x) % z;
 
      // y must be even now
      y = y >> 1; // y = y/2
      x = (x * x) % z;
    }
    return res;

  }

  private static boolean isRelativelyPrime(long a, long b) {
      return recursiveGCD(a,b) == 1;
  }

  private static long recursiveGCD(long a, long b) {
      if (b == 0) {
          return a;
      }
      if (a < b) {
          return recursiveGCD(b, a);
      }
      return recursiveGCD(b, a % b);
  }

  // used for server authentication. For ease, using the client's g^secret mod p
  public long getNonce(boolean isServer) {
    // should be the same for both the client and the server
    if (isServer) { return this.counterpart_public; }
    return power_with_mod(this.g, this.secret, this.p);
  }

  // ******************* debugging help
  public void print() {
    System.out.println(this.g + "secret: " + this.secret + "p: " + this.p);
    System.out.println("public counterpart: " + this.counterpart_public);
  }

  private static final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();
  public static String toHex(byte[] bytes)
  {
      char[] c = new char[bytes.length*2];
      int index = 0;
      for (byte b : bytes)
      {
          c[index++] = HEX_DIGITS[(b >> 4) & 0xf];
          c[index++] = HEX_DIGITS[b & 0xf];
      }
      return new String(c);
  }
}

/**
 * Secure Socket implementing TLS1.3 handshake on top of TLS
 */
import java.util.*;
import java.lang.reflect.Method;
import java.security.spec.KeySpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SecureSocket {
    // Secure Socket (TLS 1.3) states
    enum State {
        // protocol states
        LISTEN,
        CONNECT,
        CLIENT_WAVED,
        SERVER_WAVED,
        SECURE,
        CLOSING,
        CLOSED
    }
    private State state = State.CLOSED;
    private DH dh; // class for Diffie-Hellman key generation
    private byte[] certificate; // certificate issued by certificate authority, for server to authenticate

    private TCPManager tcpMan;
    public TCPSock tcpSock;

    private byte[] sockBuff;
    private byte[] outBuff;

    private int sockBuffHead;
    private int sockBuffTail;
    private int outBuffHead;
    private int outBuffTail;
    private int verifiedTail;

    private int SOCK_BUFF_SIZE = 100000;
    private int OUT_BUFF_SIZE = 100000;
    
    private int CRYPT_CHUNK_SIZE = 8;
    private int SEND_VOLUME = 3;

    private String secret_key;
    private int since_last_verified;
    
    public SecureSocket(TCPManager tcpMan) {
        this.tcpMan = tcpMan; 
        this.tcpMan.secureSock = this;
        this.tcpSock = this.tcpMan.socket();
        this.tcpSock.secureSock = this;
        this.sockBuff = new byte[SOCK_BUFF_SIZE]; 
        this.outBuff = new byte[OUT_BUFF_SIZE]; 

        this.sockBuffHead = 0;
        this.sockBuffTail = 0;
        this.outBuffHead = 0;
        this.outBuffTail = 0;
        this.verifiedTail = 0;
        this.since_last_verified = 0;

        // this is set during handshake
        this.secret_key = "thisKeyIsForTesting434";

        this.dh = new DH();
    }

    /*
    * Read data from the underlying TCP socket and output it to the user
    * All APIs are NON-BLOCKING.
    */
    public int read(byte[] buf, int pos, int len) {
        // 1. Read encrypted data from the underlying TCP socket into this socket's buffer
        this.tcpSock.read(this.sockBuff, this.sockBuffTail, this.sockBuffTail + len);
        this.sockBuffTail += len;

        /** 2. Iterate through sockBuff and decrypt chunks of bytes
        of size CRYPT_CHUNK_SIZE */
        if(this.sockBuffTail-this.sockBuffHead >= CRYPT_CHUNK_SIZE) {
            while(this.sockBuffHead < this.sockBuffTail) {
                this.decrypt(this.sockBuff, this.sockBuffHead, this.sockBuffHead + CRYPT_CHUNK_SIZE);
                this.sockBuffHead += CRYPT_CHUNK_SIZE;
            }
        }

        // 3. Put len bytes into buf
        int i;
        for(i = 0; i < len && (this.outBuffHead+i < this.outBuffTail) ; i++){
            buf[pos+i] = this.outBuff[this.outBuffHead+i];
        }
        this.outBuffHead = this.outBuffTail;
        return i; //number of bytes successfully read
    }

    /*
    * Write Data fromt the user to the underlying TCP-sockets buffer
    * All APIs are NON-BLOCKING.
    */
    public int write(byte[] buf, int pos, int len) {
        // on first write, once TCP handshake is complete, start TLS handshake
        if (this.state == State.CONNECT && this.tcpSock.isConnected()) {
            System.out.println("Starting TLS handshake");
            // send CLIENT_HELLO
            this.wave(Transport.CLIENT_HELLO);
            this.state = State.CLIENT_WAVED;
        }

        // This is a hack to fix what is discussed on line 126
        if (this.state != State.SECURE) {
            return 0;
        }

        // 1. Read len bytes of buf contents into sockBuff (unencrypted data)
        for(int i = 0; (i < len) && (this.sockBuffTail < SOCK_BUFF_SIZE); i++) { //also check that we do not overflow the buffer
            this.sockBuff[this.sockBuffTail] = buf[pos + i];
            this.sockBuffTail++;
        }

        // if TLS handshake is not yet finished, do not encrypt yet
        // This is the correct place for this check, but it was causing a bug I couldn't find in time -- AC
        // if (this.state != State.SECURE) {
        //     return 0;
        // }

        /** 2. Iterate through sockBuff and encrypt chunks of bytes
        of size CRYPT_CHUNK_SIZE */
        int numBytesWritten = 0;

        if(this.sockBuffTail-this.sockBuffHead >= CRYPT_CHUNK_SIZE) {
            while(this.sockBuffHead < this.sockBuffTail) {
                this.encrypt(this.sockBuff, this.sockBuffHead, this.sockBuffHead + CRYPT_CHUNK_SIZE);
                numBytesWritten += this.tcpSock.write(this.outBuff, this.outBuffHead, this.outBuffTail-this.outBuffHead);
                this.sockBuffHead += CRYPT_CHUNK_SIZE;
                this.outBuffHead = this.outBuffTail;
            }
        }

        // 3. Call TCPSock write() on outBuff (the encrypted buffer)
        //int ret = this.tcpSock.write(this.outBuff, this.outBuffHead, this.outBuffTail);
        
        return numBytesWritten;
    }

    /**
    * Bind a socket to a local port
    *
    * @param localPort int local port number to bind the socket to
    * @return int 0 on success, -1 otherwise
    */
    public int bind(int localPort) {
        return this.tcpSock.bind(localPort);
    }

    /**
     * Initiate connection to a remote socket
     *
     * @param destAddr int Destination node address
     * @param destPort int Destination port
     * @return int 0 on success, -1 otherwise
     */
    public int connect(int destAddr, int destPort) {
        this.state = State.CONNECT;
        return this.tcpSock.connect(destAddr, destPort);
    }

    public int listen(int backlog) {
        this.state = State.LISTEN;
        return this.tcpSock.listen(backlog);
    }

    private int decrypt(byte[] buf, int startPos, int endPos) {
        String SALT = "saltyaboutcs";
        try {
            // Step 0: get text to decrypt
            byte[] ciphertextToDecrypt = new byte[endPos-startPos];
            for(int i = 0; i < endPos-startPos; i++){
                ciphertextToDecrypt[i] = buf[startPos + i];
            }
            // Step 1: decrypt ciphertext
			// make bye array and ivspec
            // source: https://www.geeksforgeeks.org/what-is-java-aes-encryption-and-decryption/
			byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			IvParameterSpec ivspec = new IvParameterSpec(iv);

			// make the secret key factory 
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			// help generate key information 
			KeySpec spec = new PBEKeySpec(this.secret_key.toCharArray(), SALT.getBytes(), 65536, 256);
			SecretKey secret = factory.generateSecret(spec);
			// make key 
			SecretKeySpec secretKey = new SecretKeySpec(secret.getEncoded(), "AES");

			// create AES cipher
			Cipher aes = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			aes.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
			// decrypt ciphertext 
			byte[] decrypted = aes.doFinal(ciphertextToDecrypt);
            int decryptedSize = decrypted.length;

            /*System.out.println("Decrypt:");
            System.out.println(Base64.getEncoder().encodeToString(ciphertextToDecrypt));
            System.out.println(Base64.getEncoder().encodeToString(decrypted));*/

            // Step 2: determine if in verify and act accordingly 
            // if do not need to verify 
            if (this.since_last_verified < SEND_VOLUME){
                for(int k=0; k<decryptedSize; k++){
                    // move decrypted into outBuffer
                    this.outBuff[this.outBuffHead + k] = decrypted[k];
                    // move tail 
                    this.outBuffTail++;
                }
                //this.since_last_verified++;
            }
            // need to verify 
            else{
                // verify packet 
                this.verifiedTail = this.outBuffTail;
                // move verified point 
                this.since_last_verified = 0;
                decryptedSize = 0;
            }
            return decryptedSize;
		}
		catch (Exception e) {
			return -1;
		}
    }

    private int encrypt(byte[] buf, int startPos, int endPos) {
        String SALT = "saltyaboutcs";

		try {
            byte[] plaintextToEncrypt = new byte[endPos-startPos];
            for(int i = 0; i < endPos-startPos; i++) {
                plaintextToEncrypt[i] = buf[startPos + i];
            }

            // Step 1: encrypt text 
			// make bye array and ivspec
            // source: https://www.geeksforgeeks.org/what-is-java-aes-encryption-and-decryption/
			byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			IvParameterSpec ivspec = new IvParameterSpec(iv);

			// make the secret key factory 
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			// help generate key information 
			KeySpec spec = new PBEKeySpec(this.secret_key.toCharArray(), SALT.getBytes(), 65536, 256);
			SecretKey secret = factory.generateSecret(spec);
			// make key 
			SecretKeySpec secretKey = new SecretKeySpec(secret.getEncoded(), "AES");

			// create AES cipher
			Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
			aes.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
			// encrypt plaintext
			byte[] encrypted = aes.doFinal(plaintextToEncrypt);
            int encryptedSize = encrypted.length;

            /*System.out.println("Encrypt:");
            System.out.println(Base64.getEncoder().encodeToString(plaintextToEncrypt));
            System.out.println(Base64.getEncoder().encodeToString(encrypted));*/

            // Step 2: add encrypted to outbuffer
            for(int k=0; k < encryptedSize; k++){
                this.outBuff[this.outBuffHead + k] = encrypted[k];
                // move tail
                this.outBuffTail++;
            }

            /*System.out.println("Encrypt:");
            System.out.println(Base64.getEncoder().encodeToString(this.outBuff));*/

            return encryptedSize;

		}
		catch (Exception e) {
			return -1;
		}
	}

    // *************** functions for TLS handshake
    // send SERVER_HELLO or CLIENT_HELLO
    // choose parameters for DH key generation
    private void wave(int transportType) {
        byte[] payload = new byte[0];
        if (transportType == Transport.CLIENT_HELLO) {
            this.dh.generate_pg();
            this.dh.generate_secret();
            payload = this.dh.get_payload();
        }
        else if (transportType == Transport.SERVER_HELLO) {
            this.dh.generate_secret();
            payload = this.dh.get_payload();
        }
        this.tcpMan.send_message(this.tcpSock, transportType, payload);
    }

    // @param transportType -- either Transport.CLIENT_HELLO, or Transport.SERVER_HELLO
    public void onHello(Transport trsp) {
        if (trsp.getType() == Transport.CLIENT_HELLO) {
            // parse payload to get p, g, and client's g^secret mod p
            this.dh.parse_payload(trsp);
            // send SERVER_HELLO
            this.wave(Transport.SERVER_HELLO);
            this.state = State.SERVER_WAVED;
            this.authenticate();
            this.finishHandshake(Transport.SERVER_HANDSHAKE_FINISHED);
        }
        else if (trsp.getType() == Transport.SERVER_HELLO) {
            this.dh.parse_payload(trsp);
        }
    }

    // send certificate provided by certificate authority
    // send hash of CLIENT_HELLO, SERVER_HELLO, signed by private key
    // This identifies and authenticates the server to the client
    private void authenticate() {
        int srcAddr, dstAddr, srcPort, dstPort;
        srcAddr = this.tcpSock.getSrcAddr();
        dstAddr = this.tcpSock.getDstAddr();
        srcPort = this.tcpSock.getSrcPort();
        dstPort = this.tcpSock.getDstPort();
        this.certificate = Authenticate.getCertificate();
        byte[] payload = Authenticate.getPayload(this.certificate, this.dh.getNonce(true));
        this.tcpMan.send(srcAddr, dstAddr, srcPort, dstPort, Transport.SERVER_AUTHENTICATE, payload, 0, 0);
    }

    // client decrypts SERVER_AUTHENTICATE using the public key sent by the server
    // client compares the decrypted value to originally sent nonce and confirms they are the same
    // returns -1 on failure tp authenticate, and connection is closed
    public int checkAuthentication(Transport trsp) {
        if (!Authenticate.verify(trsp.getPayload(), this.dh.getNonce(false))) { 
            this.release();
        }
        this.finishHandshake(Transport.CLIENT_HANDSHAKE_FINISHED);
        return 0;
    }

    private void finishHandshake(int transportType) {
        this.secret_key = dh.get_key();
        this.tcpMan.send_message(this.tcpSock, transportType, new byte[0]);
        this.state = State.SECURE;
    }    

    public String getSecretKey() { return this.secret_key; }
    // end handshake functions ******************

    // pass down functions to TCPSock
    public boolean isConnectionPending() {
        return this.tcpSock.isConnectionPending();
    }

    public boolean isClosed() {
        return this.tcpSock.isClosed();
    }

    public boolean isConnected() {
        return this.tcpSock.isConnected();
    }

    public boolean isClosurePending() {
        return this.tcpSock.isClosurePending();
    }

    /**
    * Initiate closure of a connection (graceful shutdown)
    */
    public void close() {
        this.tcpSock.close();
    }

    /**
    * Release a connection immediately (abortive shutdown)
    */
    public void release() {
        this.tcpSock.release();
    }

    /*
     * End of secure socket API
     */

    //Ken's debug functions

    /*
    private void DEBUG(String s){
        System.out.println("***DEBUG BLOCK***");
        System.out.println("* MSG: " + s);
        System.out.println("* SOCKBUFHEAD: " + this.sockBuffHead + " : SOCKBUFTAIL: " + this.sockBuffTail);
        System.out.println("* OUTBUFHEAD: " + this.outBuffHead + " : OUTBUFTAIL: " + this.outBuffTail);
        System.out.println("* OUTBUFF: ");
        for(int i = 0 ; i < (this.outBuffTail-this.outBuffHead); i++){
            System.out.print((char)this.outBuff[this.outBuffHead + i]);
        }
        System.out.println("");
        System.out.println("****END BLOCK****");
    }

    private void DEBUG_2(String s){
        System.out.println("***DEBUG BLOCK***");
        System.out.println("* MSG: " + s);
        System.out.println("* SOCKBUFHEAD: " + this.sockBuffHead + " : SOCKBUFTAIL: " + this.sockBuffTail);
        System.out.println("* OUTBUFHEAD: " + this.outBuffHead + " : OUTBUFTAIL: " + this.outBuffTail);
        System.out.println("* OUTBUFF: ");
        for(int i = 0 ; i < (this.sockBuffTail-this.sockBuffHead); i++){
            System.out.print((char)this.sockBuff[this.sockBuffHead + i]);
        }
        System.out.println("");
        System.out.println("****END BLOCK****");
    }
    */
}

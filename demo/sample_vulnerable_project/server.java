// Sample Java server with quantum-vulnerable crypto
import java.security.*;
import javax.crypto.*;

public class Server {
    public static void main(String[] args) throws Exception {
        // RSA key generation — quantum vulnerable
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        // RSA encryption
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());

        // ECDSA signing — quantum vulnerable
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC");
        ecKpg.initialize(256);

        // Weak hash
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update("data".getBytes());
    }
}

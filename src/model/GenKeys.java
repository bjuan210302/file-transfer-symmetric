package model;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import javax.crypto.spec.SecretKeySpec;

public class GenKeys {
	public Key generateKey(byte[] sharedKey){
		String AESKeyFilename = "Files/AESKeyFile.txt";
		
        byte[] byteKey = new byte[16];
        for(int i = 0; i < 16; i++) {
            byteKey[i] = sharedKey[i];
        }
        
        try {
            Key key = new SecretKeySpec(byteKey, "AES");
            FileOutputStream fos = new FileOutputStream(AESKeyFilename);
            fos.write(key.getEncoded());
            fos.close();
            return key;
        } catch(IllegalArgumentException e) {
            System.err.println("Error while generating key: " + e);
        } catch(IOException e) {
        	System.err.println("Error while saving key in text file: " + e);
        }

        return null;
    }

}

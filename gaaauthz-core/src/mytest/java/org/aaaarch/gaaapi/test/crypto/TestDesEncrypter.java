package org.aaaarch.gaaapi.test.crypto;

import java.security.Key;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.aaaarch.crypto.CryptoData;
import org.aaaarch.crypto.DesEncrypter;
import org.aaaarch.utils.HelpersReadWrite;
import org.w3c.dom.Document;

public class TestDesEncrypter {

    public static void main(String[] args)
    {
    	try {
            // Generate a temporary key. In practice, you would save this key.
            // See also e464 Encrypting with DES Using a Pass Phrase.
            SecretKey key1 = KeyGenerator.getInstance("DES").generateKey();
            SecretKey key2 = KeyGenerator.getInstance("DES").generateKey();
        
            // Create encrypter/decrypter class
            //DesEncrypter encrypter = new DesEncrypter(key);
            DesEncrypter encrypter1 = new DesEncrypter("aaBBccDDeeFF");
            DesEncrypter encrypter2 = new DesEncrypter("aaBBccDDeeFF");
        
       	   	System.out.println("Running Examples for DES Encryption and Decryption: \n");
       		System.out.println("Select Encryption/Decryption option ( \n" + 
       				"1 - Encrypt/Decrypt string\n" + 
       				"2 - Encrypt/Decrypt string - input string\n" + 
       				"3 - Create and encrypt an element Subject name\n" +  
       				"");
       		int s = HelpersReadWrite.readStdinInt();			
       		//printKeyInfo (keyalias); 
       		switch(s) {
       		case 1: { 
            // Encrypt
       		String anystring = "Don't tell anybody!";
       		String encrypted = encrypter1.encrypt(anystring);
            System.out.println("Original string is:" + anystring);
            System.out.println("Encrypted string is:" + encrypted);
            
            // Decrypt
            String decrypted = encrypter2.decrypt(encrypted);
            System.out.println("Decrypted string is:" + decrypted);
            
			return;}
       		case 2: { 
       	    // Encrypt
       	    String anystring = HelpersReadWrite.readInString();
       	    String encrypted = encrypter1.encrypt(anystring);
       	    System.out.println("Original string is:" + anystring);
       	    System.out.println("Encrypted string is:" + encrypted);
       	            
       	    // Decrypt
       	    String decrypted = encrypter2.decrypt(encrypted);
       	    System.out.println("Decrypted string is:" + decrypted);
       	            
       		return;}
       		case 3: { 

       		// AuthnToken modelling
            String subject = "dude@big.lebowsky.ca";
            String encsubject = CryptoData.doEncryptData(subject, "keypass");
            String deccsubject = CryptoData.doDecryptData(encsubject, "keypass");
            
            boolean confirm = CryptoData.doVerifyEncryptedData(subject, encsubject, "keypass");
            //boolean confirm = true;
            System.out.println("\nSubject = " + subject + "; EncryptedSubject:" + encsubject);
            System.out.println("\nEncryptedSubject:" + encsubject + "; Subject = " + subject);
    		System.out.println("\nSubject and ConfirmationData are: " + (confirm ? "Correct" : "Not correct") );
				return;}
       		}
            
        } catch (Exception e) {
        	e.printStackTrace();
        }
    }      

}

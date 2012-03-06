/*
 * Created on Feb 8, 2005
 *
 */
package org.aaaarch.tvs;

import java.security.SecureRandom;

/**
 * @author demch
 * 
 *  Generates a random/unique identifier
 *
 */
public class IDgenerator {

    public static String generateID() {
    	StringBuffer id = new StringBuffer();
        byte[] buf=new byte[32];
        SecureRandom random = new SecureRandom();
        //clear buffer??
        do
        {
            random.nextBytes(buf);
        } while ((buf[0] & 15) < 10);
        
        for (int i=0; i<32; i++)
            id.append(Character.forDigit(buf[i] & 15, 16));
        
        return id.toString();
    }

    public static String generateID(int size) {
    	//StringBuffer id = new StringBuffer();
        byte[] buf = new byte[size];
        SecureRandom random = new SecureRandom();

        random.nextBytes(buf);
        // SAML2.0 style "_hexIdIdId"
        //String randomstr =  "_".concat(new String(Hex.encode(buf)));
        //String randomstr =  new String(Hex.encode(buf));
        
        String randomstr = toHexString(buf);
        return randomstr;
    }
    
    public static String toHexString(byte[]bytes) {
        StringBuilder sb = new StringBuilder(bytes.length*2);
        for(byte b: bytes)
          sb.append(Integer.toHexString(b+0x800).substring(1));
        return sb.toString();
    }

}

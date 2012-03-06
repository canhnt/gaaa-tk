package org.aaaarch.crypto;

import java.security.Key;
import java.security.Provider;
import java.security.Security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HMACprocessor {

	//private File keyFile;
	private String keyString;
	private static byte [] keyBytes;

	private static String crypto4hash = "2badfec5c0de4";

	//private File dataFile;
	private String dataString;
	private static byte [] dataBytes;
	  
	//protected boolean noHex = false;

	public static final String DEFAULT_ALGO = "HMacSHA1";
	private static String alg = DEFAULT_ALGO;
	//public static final String DEFAULT_ALGO = "HMacMD5";
	public static final int MIN_LENGTH = 8;
	public static final int BUF_LENGTH = 256;

	static HMACprocessor hmacp = new HMACprocessor();
	
    public HMACprocessor() {
    }
        
	public HMACprocessor (String datastring, String keystring, String algorithm) throws Exception {
        this.dataString = datastring;
        this.keyString = keystring;
        this.alg = algorithm;
    } 
	
	public byte[] computeMac() throws HMACProcessorException {
		    Mac hm = null;
		    byte [] result = null;

		    try {
		      hm = Mac.getInstance(alg);

		      Key k1 = new SecretKeySpec(keyBytes, 0, keyBytes.length, alg);
		      hm.init(k1);
		      result = hm.doFinal(dataBytes);
		    }
		    catch (Exception e) {
		      throw new HMACProcessorException("Bad algorithm or crypto library problem", e);
		    }
		    return result;
		  }
	
	// HMAC generated of Data string and Key secret string
	// Used to compute TokenKey
	public static byte[] computeHMAC(String datastring, String keystring, 
			String algorithm) throws HMACProcessorException {

	   keyBytes = keystring.getBytes();
	   dataBytes = datastring.getBytes();
	   
	   if ((algorithm != null) && (!algorithm.equals("HMacSHA1"))) {
		   alg = algorithm;
	   }
	   
	   try {
	   Provider sp = new com.sun.crypto.provider.SunJCE();
	   Security.addProvider(sp);
	   }
	   catch (Exception e) {
	   throw new HMACProcessorException("Problem loading crypto provider", e);
	   }
	   
	   byte [] hmac = hmacp.computeMac();
	   
       //System.out.println("Compute tokenKey: key bytes = " + HelpersHexConverter.byteArrayToHex(keyBytes) + 
	   //		"; \nCompute token: hm-result = " + HelpersHexConverter.byteArrayToHex(hmac));
	   return hmac;
	}	
	 
	// HMAC generated of Data string and binary TokenKey 
	// Used to compute Token
	public static byte[] computeHMAC(String datastring, byte[] tokenkey, 
			String algorithm) throws HMACProcessorException {
	   byte[] result;

	   keyBytes = tokenkey;
	   dataBytes = datastring.getBytes();
	   
	   if ((algorithm != null) && (!algorithm.equals("HMacSHA1"))) {
		   alg = algorithm;
	   }
	   
	   try {
	   Provider sp = new com.sun.crypto.provider.SunJCE();
	   Security.addProvider(sp);
	   }
	   catch (Exception e) {
	   throw new HMACProcessorException("Problem loading crypto provider", e);
	   }
	   
	   byte [] hmac = hmacp.computeMac();
	   
       //System.out.println("Compute token: key bytes = " + HelpersHexConverter.byteArrayToHex(keyBytes) + 
	   //		"; \nCompute token: hm-result = " + HelpersHexConverter.byteArrayToHex(hmac));
	   return hmac;
	}	

	public static String getCrypto4hashTest () {
		return crypto4hash;
	}
	

}

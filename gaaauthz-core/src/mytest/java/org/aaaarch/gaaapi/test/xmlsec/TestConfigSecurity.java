/*
 * Created on Nov 15, 2004
 *
 */
package org.aaaarch.gaaapi.test.xmlsec;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.w3c.dom.Element;

import org.aaaarch.config.KeyStoreConfig;
import org.apache.xml.security.utils.XMLUtils;

/**
 * @author demch
 *
 */
public class TestConfigSecurity {

   public static void getSecurityConfig() throws Exception {
	
	String keyset = "gaaa-nrp";
   	List checkconfsec = new ArrayList();
   	
	checkconfsec = KeyStoreConfig.getConfigKeys(keyset);
	
	//
    String keystoreType = (String) checkconfsec.get(0);
    String keystoreFile = (String) checkconfsec.get(1);
    String keystorePass = (String) checkconfsec.get(2);
    String privateKeyAlias = (String) checkconfsec.get(3);
    String privateKeyPass = (String) checkconfsec.get(4);
    String certificateAlias = (String) checkconfsec.get(5);
	
	//

	System.out.print ("\n###Echo TestConfigSecurity\n" 
			+ "keystoreType=" + keystoreType + "\n" 
    		+ "keystoreFile=" + keystoreFile + "\n" 
			+ "keystorePass=" + keystorePass + "\n"
			+ "privateKeyAlias=" + privateKeyAlias + "\n"
			+ "privateKeyPass=" + privateKeyPass + "\n"
			+ "certificateAlias=" + certificateAlias + "\n");

	KeyStore ks = KeyStore.getInstance(keystoreType);
    FileInputStream fis = new FileInputStream(keystoreFile);

    ////FileOutputStream fus = new FileOutputStream(outFile);
    ////System.out.print(fis.toString());
    
    //load the keystore
    ks.load(fis, keystorePass.toCharArray());

    //get the private key for signing.
    PrivateKey  privateKey = (PrivateKey) ks.getKey(privateKeyAlias,
                                           privateKeyPass.toCharArray());
    Certificate cert = (Certificate) ks.getCertificate(certificateAlias);
    
    System.out.print("\n###Private key: \n" + privateKey.toString()); //***
    System.out.print("\n###Certificate: \n" + cert.toString()); //***
    
    ////
    
   }

	public static void main(String args[]) throws IOException {
		try {
			System.out.println("Running test for PEP/PDP Authorisation components (aaauthreach prj)");
			System.out.println( 
				"1 - get Security Config default; \n" +
				"2 - get named keys; \n" +
				"4 - generate keys ALL; \n" +
				"5 - generate keys INTERACTIVE; \n" +
				"");
		int s = readStdinInt();			
		switch(s) {
			case 0: { 
				return;}
			
			case 1: { 
				getSecurityConfig();
				return;}
			
			case 2: { 
				getSecurityConfig();
				return;}

			case 4: { 
				System.out.println("Generating keys for Phosphorus GAAA-NRP"); 
				generateKeysAll();
				return;}
			case 5: { 
			return;}
			
			}
			System.out.println("OK");
			System.exit(0);
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
	  }
	
	private static void generateKeysAll() throws KeyStoreException {
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
	
		//PrivateKey k1 = KeyTool.
	}

	////////////////////////////////	
	// Input menu number (integer)

	public static int readStdinInt (){
		String line = null;
		int val = 0;
		try {
			BufferedReader is = new BufferedReader(
				new InputStreamReader(System.in));
				line = is.readLine();
				val = Integer.parseInt(line);
			} 
		catch (NumberFormatException ex) 
		{
		System.err.println("Not a valid number: " + line);
		} 
		catch (IOException e) 
		{
		System.err.println("Unexpected IO ERROR: " + e);
		}
		//System.out.println("I read this number: " + val);
		return val;
	}
	
	public static void saveDOMdoc (org.w3c.dom.Document doc, String filename) throws Exception {
	    // save file from DOM doc
	    FileOutputStream f = new FileOutputStream(filename);
	    XMLUtils.outputDOMc14nWithComments(doc, f);
	    f.close();
	    //System.out.println("Wrote echo DOM doc to " + filename);
	}

	public static void writerFile(String text, String fileName) throws IOException {
		PrintWriter out =
			new PrintWriter(new BufferedWriter(new FileWriter(fileName)));
		out.print(text);
		out.close();
	}	

	public static org.w3c.dom.Document readFileToDOM (String filename) throws Exception {
       // start xml document processing part
       javax.xml.parsers.DocumentBuilderFactory dbf =
          javax.xml.parsers.DocumentBuilderFactory.newInstance();

       //XML Signature needs to be namespace aware
       dbf.setNamespaceAware(true);

       javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
       //org.w3c.dom.Document docnew = db.newDocument();

       // reading document
       System.out.print("file to read " + filename + "\n");
       org.w3c.dom.Document doc = db.parse(filename);

       // save echo file after parsing
       //String echoDOM = "echoDOMparse.xml";
       //saveDOMdoc (doc, echoDOM);
       //System.out.println("Wrote echo after parsing to DOM to " + echoDOM);

       // print echo file after parsing
      	//printDOMdoc(doc);
       return doc;
	}	
	public static PrivateKey getPrivKey (List keyset) throws Exception {

		//List keyset = ConfigSecurity.getConfigSecurity(keyalias);
 	    String keystoreType = (String) keyset.get(0);
 	    String keystoreFile = (String) keyset.get(1);
 	    String keystorePass = (String) keyset.get(2);
 	    String privateKeyAlias = (String) keyset.get(3);
 	    String privateKeyPass = (String) keyset.get(4);
 	    String certificateAlias = (String) keyset.get(5);

       // Retrieving key information
       KeyStore ks = KeyStore.getInstance(keystoreType);
       FileInputStream fis = new FileInputStream(keystoreFile);
       //load the keystore
       ks.load(fis, keystorePass.toCharArray());
       //get the private key for signing.
       PrivateKey privateKey = (PrivateKey) ks.getKey(privateKeyAlias,
                                              privateKeyPass.toCharArray());
        System.out.print("\n###Private key: \n" + privateKey.toString());
       return privateKey;
	
	} 
	public static X509Certificate[] getCert (List keyset) throws Exception {

		X509Certificate[] issuerCert = null;

		//List keyset = ConfigSecurity.getConfigSecurity(keyalias);
 	    String keystoreType = (String) keyset.get(0);
 	    String keystoreFile = (String) keyset.get(1);
 	    String keystorePass = (String) keyset.get(2);
 	    String privateKeyAlias = (String) keyset.get(3);
 	    String privateKeyPass = (String) keyset.get(4);
 	    String certificateAlias = (String) keyset.get(5);

       // Retrieving key information
       KeyStore ks = KeyStore.getInstance(keystoreType);
       FileInputStream fis = new FileInputStream(keystoreFile);
       //load the keystore
       ks.load(fis, keystorePass.toCharArray());
       //get the private key for signing.
       //PrivateKey privateKey = (PrivateKey) ks.getKey(privateKeyAlias, privateKeyPass.toCharArray());
        //System.out.print("\n###Private key: \n" + privateKey.toString());
       //Add in the KeyInfo for the certificate that we used the private key of
       //X509Certificate cert = (X509Certificate) ks.getCertificate(certificateAlias);
       //X509Certificate[] certs = (X509Certificate) ks.getCertificateChain(certificateAlias);
		//issuerCert = convertChain(ks.getCertificateChain(certificateAlias));
       
       //PublicKey pubbkey = cert.getPublicKey();
       
       return issuerCert;
	        
	} 
   
   
}
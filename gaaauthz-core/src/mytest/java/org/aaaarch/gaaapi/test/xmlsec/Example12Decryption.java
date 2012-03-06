/*
 * Copyright  2004-2005 AIRG.
 *
 *
 */
package org.aaaarch.gaaapi.test.xmlsec;


import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.aaaarch.config.KeyStoreConfig;
import org.aaaarch.utils.HelpersReadWrite;
import org.apache.xml.security.utils.EncryptionConstants;
import org.apache.xml.security.utils.JavaUtils;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import org.apache.xml.security.encryption.XMLCipher;

/**
 * The example to demonstrate how to decrypt data inside an xml document.
 *
 * @author $Author: demch $
*/
public class Example12Decryption {

    /** {@link org.apache.commons.logging} logging facility */
    static org.apache.commons.logging.Log log = 
        org.apache.commons.logging.LogFactory.getLog(
            Example12Decryption.class.getName());

    static {
        org.apache.xml.security.Init.init();
    }

    public static Document decryptDocument (Document document, Key kek) throws Exception {

  	   	//String jceAlgoKey = "DESede";
        //String kekfname = "data/keystore/xmlsec/symkeystore/kek1";
        //Key skek = loadKeyEncryptionKey(jceAlgoKey, kekfname);
    	
        //printDOMdoc(document);
        
    	Element encryptedDataElement =
            (Element) document.getElementsByTagNameNS(
                EncryptionConstants.EncryptionSpecNS,
                EncryptionConstants._TAG_ENCRYPTEDDATA).item(0);
        //
        if (encryptedDataElement == null)
        {System.out.print("\n###encrypted element is null");} else {
        	System.out.print("\n###encrypted element is not null");
        }
        Node cval = document.getElementsByTagNameNS(EncryptionConstants.EncryptionSpecNS,
                EncryptionConstants._TAG_CIPHERVALUE).item(0);
        if (cval == null)
        {System.out.print("\n###CipherValue element is null");} else {
        	System.out.print("\n###CipherValue element is not null");
        }
        // wrong //System.out.print("\n###CipherValue element: " + cval.getNodeValue() + "\n");
        //printDOMdoc(celm);
        /*
         * Load the key to be used for decrypting the xml data
         * encryption key.
         */
        //Key kek = loadKeyEncryptionKey();
        System.out.print("\n###key encryption key: " + kek.toString() + "\n");
        //String providerName = "BC";

        XMLCipher xmlCipher = XMLCipher.getInstance();
        /*
         * The key to be used for decrypting xml data would be obtained
         * from the keyinfo of the EncrypteData using the kek.
         */
        xmlCipher.init(XMLCipher.DECRYPT_MODE, null);
        xmlCipher.setKEK(kek);
        /*
         * The following doFinal call replaces the encrypted data with
         * decrypted contents in the document.
         */
        xmlCipher.doFinal(document, encryptedDataElement);

        //outputDocToFile(document, "decrypted-doc.xml");
        return document;
    }
    
    private static Document loadEncryptionDocument(String infile) throws Exception {

        File encryptionFile = new File(infile);
        javax.xml.parsers.DocumentBuilderFactory dbf =
            javax.xml.parsers.DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
        Document document = db.parse(encryptionFile);
        System.out.println(
            "Encryption document loaded from " +
            encryptionFile.toURL().toString());
        return document;
    }

    private static SecretKey loadKeyEncryptionKey(String jceAlgorithmName, String kekfname) 
    	throws Exception {

        File kekFile = new File(kekfname);

        DESedeKeySpec keySpec =
            new DESedeKeySpec(JavaUtils.getBytesFromFile(kekfname));
        SecretKeyFactory skf =
             SecretKeyFactory.getInstance(jceAlgorithmName);
        SecretKey key = skf.generateSecret(keySpec);
         
        System.out.println(
            "Key encryption key loaded from " + kekFile.toURL().toString());
        
        return key;
    }

    private static SecretKey loadKeyEncryptionKey() 
	throws Exception {
  	   	String jceAlgorithmName = "DESede";
        String kekfname = "data/keystore/xmlsec/symkeystore/kek";

    File kekFile = new File(kekfname);

    DESedeKeySpec keySpec =
        new DESedeKeySpec(JavaUtils.getBytesFromFile(kekfname));
    SecretKeyFactory skf =
         SecretKeyFactory.getInstance(jceAlgorithmName);
    SecretKey key = skf.generateSecret(keySpec);
     
    System.out.println(
        "Key encryption key loaded from " + kekFile.toURL().toString());
    
    return key;
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
		    //System.out.print("\n###Private key: \n" + privateKey.toString() + "\n");
		    return privateKey;
		}

	public static PublicKey getPublicKey (List keyset) throws Exception {
		
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
	         X509Certificate cert =
	            (X509Certificate) ks.getCertificate(certificateAlias);

	         //System.out.print("\n### X.509 content: \n" + cert.toString()); //***  
	         
		    PublicKey pubKey = (PublicKey) cert.getPublicKey();
		    //System.out.print("\n###Public key: \n" + pubKey.toString() + "\n");
		    return pubKey;
		}
    
    
    private static void outputDocToFile(Document doc, String fileName)
        throws Exception {
        File encryptionFile = new File(fileName);
        FileOutputStream f = new FileOutputStream(encryptionFile);

        TransformerFactory factory = TransformerFactory.newInstance();
        Transformer transformer = factory.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(f);
        transformer.transform(source, result);

        f.close();
        System.out.println(
            "Wrote document containing decrypted data to " +
            encryptionFile.toURL().toString());
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
        String echoDOM = "echoDOMparse.xml";
        saveDOMdoc (doc, echoDOM);
        System.out.println("Wrote echo after parsing to DOM to " + echoDOM);

        // print echo file after parsing
       	//printDOMdoc(doc);
        return doc;
 	}	
	
 	public static void printKeyInfo (String keyalias) throws Exception {
 	   	List checkconfsec = new ArrayList();

 	   	checkconfsec = KeyStoreConfig.getConfigKeys(keyalias);

 		String keystoreType = (String) checkconfsec.get(0);
 		String keystoreFile = (String) checkconfsec.get(1);
 		String keystorePass = (String) checkconfsec.get(2);
 		String privateKeyAlias = (String) checkconfsec.get(3);
 		String privateKeyPass = (String) checkconfsec.get(4);
 		String certificateAlias = (String) checkconfsec.get(5);
 		//

 		System.out.print ("\n###Echo Key information\n" 
 				+ "keystoreType=" + keystoreType + "\n" 
 				+ "keystoreFile=" + keystoreFile + "\n" 
 				+ "keystorePass=" + keystorePass + "\n"
 				+ "privateKeyAlias=" + privateKeyAlias + "\n"
 				+ "privateKeyPass=" + privateKeyPass + "\n"
 				+ "certificateAlias=" + certificateAlias + "\n\n"); 		
 	}

 	public static void printDOMdoc (org.w3c.dom.Document doc) throws Exception {
        // print DOM doc
        ByteArrayOutputStream f = new ByteArrayOutputStream();
        XMLUtils.outputDOMc14nWithComments(doc, f);
        f.close();
        System.out.println("\n" + f);
 	}
 	
 	public static void saveDOMdoc (org.w3c.dom.Document doc, String filename) throws Exception {
        // save file from DOM doc
        FileOutputStream f = new FileOutputStream(filename);
        XMLUtils.outputDOMc14nWithComments(doc, f);
        f.close();
        //System.out.println("Wrote echo DOM doc to " + filename);
 	}
 	
 	private static void decryptorTest(Document document, Key kek) throws Exception {

 		//Document document = loadEncryptionDocument("encsymetric-doc.xml");

        Element encryptedDataElement =
            (Element) document.getElementsByTagNameNS(
                EncryptionConstants.EncryptionSpecNS,
                EncryptionConstants._TAG_ENCRYPTEDDATA).item(0);

        /*
         * Load the key to be used for decrypting the xml data
         * encryption key.
         */
  	   	String jceAlgorithmName = "DESede";
        String kekfname = "data/keystore/xmlsec/symkeystore/kek";

        //Key kek = loadKeyEncryptionKey(jceAlgorithmName, kekfname);

        //String providerName = "BC";

        XMLCipher xmlCipher = XMLCipher.getInstance();
        /*
         * The key to be used for decrypting xml data would be obtained
         * from the keyinfo of the EncrypteData using the kek.
         */
        xmlCipher.init(XMLCipher.DECRYPT_MODE, null);
        xmlCipher.setKEK(kek);
        /*
         * The following doFinal call replaces the encrypted data with
         * decrypted contents in the document.
         */
        xmlCipher.doFinal(document, encryptedDataElement);

        outputDocToFile(document, "decrypted-doc.xml");
 		
 	}
    
    public static void main(String unused[]) throws Exception {
    	
  		//Receive parameters for the pubkey keystore
  	  	String keyalias = "cnl01";
  	   	List checkconfsec = new ArrayList();
  	   	List keyset = KeyStoreConfig.getConfigKeys(keyalias);
  	   	Key privkey = getPrivKey (keyset);
  	   	Key pubkey = getPublicKey (keyset);
        Key privkek = privkey;
  	   	
        //Type/Algorithm for Key encryption key
  	   	String jceAlgoKey = "DESede";
        String kekdir = "data/keystore/xmlsec/symkeystore/";
        //Key skek = loadKeyEncryptionKey(jceAlgoKey, (kekdir + "kek1"));
/////////
        //Document docencr = loadEncryptionDocument("encsymetric-doc.xml");
  		//printDOMdoc(document);
    	//decryptorTest(docencr, skek);

       	try {   	
       	   	System.out.println("Running Examples for XML Decryption types for AAARequest");
       		System.out.println("Select Encryption option ( \n" + 
       				"1 - Decrypt test doc using symmetric key,\n" + 
       				"2 - Decrypt an element in the test doc using symmetric key,\n" + 
       				"3 - Decrypt ext doc using symmetric key,\n" + 
       				"4 - Decrypt doc using PKI private key,\n" + 
       				"5 - Decrypt an element in the ext doc using symmetric keys" 
					);
       		int s = HelpersReadWrite.readStdinInt();			
       		//printKeyInfo (keyalias); 
       		switch(s) {
       			case 1: { 
       		    	Document doc1encsym = loadEncryptionDocument("enc1sym-doc.xml");
       		        Key skek1 = loadKeyEncryptionKey(jceAlgoKey, (kekdir + "kek1"));
       				Document docdecr = decryptDocument (doc1encsym, skek1);
       				outputDocToFile(docdecr, "decrypted1sym-doc.xml"); 
       				//printDOMdoc(docdecr);
       				return;}
       			case 2: { 
       		    	Document doc2encsym = loadEncryptionDocument("enc2symelm-doc.xml");
       		        Key skek2 = loadKeyEncryptionKey(jceAlgoKey, (kekdir + "kek2"));
       				Document docdecr = decryptDocument (doc2encsym, skek2);
       				outputDocToFile(docdecr, "decrypted2symelm-doc.xml"); 
       				//printDOMdoc(docdecr);
       				return;}
       			case 3: {
       		    	Document doc3encext = loadEncryptionDocument("enc3rypted-aaareq01nons.xml");
       		        Key skek3 = loadKeyEncryptionKey(jceAlgoKey, (kekdir + "kek3"));
       		        Document docdecr = decryptDocument (doc3encext, skek3);
       				outputDocToFile(docdecr, "decrypted3symext-doc.xml"); 
       				//printDOMdoc(docdecr);
       				return;}
       			case 4: {  
       		    	Document doc4encpub = loadEncryptionDocument("enc4public-doc.xml");
       				Document docdecr = decryptDocument (doc4encpub, privkek);
       				outputDocToFile(docdecr, "decrypted4public-doc.xml"); 
       				//printDOMdoc(docdecr);
       				return;}
       			case 5: {
       		    	Document doc5encsym = loadEncryptionDocument("enc5cryptedelm-aaareq01nons.xml");
       		        Key skek5 = loadKeyEncryptionKey(jceAlgoKey, (kekdir + "kek5"));
       				Document docdecr = decryptDocument (doc5encsym,  skek5);
       				outputDocToFile(docdecr, "decrypted5symextelm-doc.xml"); 
       				//printDOMdoc(docdecr);
       				return;}
       		}
       		System.out.println("OK");
       		System.exit(0);
       	   	} catch (Exception e) {
       	   		e.printStackTrace();
       	   		System.exit(1);
       	   		}
        
        
    }
}

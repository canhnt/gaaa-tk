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
import javax.crypto.KeyGenerator;

import org.aaaarch.config.KeyStoreConfig;
import org.aaaarch.utils.HelpersReadWrite;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xml.security.utils.Constants;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.transform.TransformerFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.OutputKeys;

/**
 * The example to demonstrate how to encrypt data inside an xml document.
 *
 * @author $Author: demch $
*/
public class Example05Encryption {

    /** {@link org.apache.commons.logging} logging facility */
    static org.apache.commons.logging.Log log = 
        org.apache.commons.logging.LogFactory.getLog(
            Example05Encryption.class.getName());

    static {
        org.apache.xml.security.Init.init();
    }

    private static Document createSampleDoc() throws Exception {

 	    String savefile = "aaareq04test4xmlenc.xml";
        
        //Build a sample document. It will look something like:
        /*
         <!-- Comment before -->
        <AAA:AAARequest xmlns:AAA="http://www.aaauthreach.org/ns/#AAA" xmlns:cnl="http://example.org/#cnl" attr1="test1" attr2="test2" cnl:attr1="CNL2 test">
        <AAA:Subject Id="subject">Subject will contain SubjectID, AuthN token and Subject attributes
        </AAA:Subject>
  		<AAA:Resource>Resource element defines target resource
  		</AAA:Resource>
  		<AAA:Action>Action element will contain requestion action
  		</AAA:Action>
          */

        // start xml document part
        javax.xml.parsers.DocumentBuilderFactory dbf =
           javax.xml.parsers.DocumentBuilderFactory.newInstance();

        //XML Signature needs to be namespace aware
        dbf.setNamespaceAware(true);

        javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
        // reading document
        org.w3c.dom.Document doc = db.newDocument();

        //XMLUtils.outputDOMc14nWithComments(doc2, f1);
        
        doc.appendChild(doc.createComment(" Comment before "));

        // root element is AAARequest
        Element root = doc.createElementNS("http://www.aaauthreach.org/ns/#AAA",
                                           "AAA:AAARequest");

        root.setAttribute("Id", "CNLhashID#");
        root.setAttributeNS(null, "version", "2.0");
        root.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:cnl", "http://www.telin.nl/ns/#cnl");
        root.setAttributeNS("http://www.telin.nl/ns/#cnl", "cnl:attr1", "CNL2test#");
        root.appendChild(doc.createTextNode("\n"));

        root.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:AAA", "http://www.aaauthreach.org/ns/#AAA");

        doc.appendChild(root);

        Element subject = doc.createElementNS("http://www.aaauthreach.org/ns/#AAA", "AAA:Subject");
        subject.appendChild(doc.createTextNode("Subject element will contain the SubjectID, AuthN token and Subject attributes\n"));
        //subject.setAttributeNS("http://www.aaauthreach.org/ns/#AAA", "Id", "subject");
        subject.setAttribute("Id", "subject");
        root.appendChild(subject);
        root.appendChild(doc.createTextNode("\n"));

        Element resource = doc.createElementNS("http://www.aaauthreach.org/ns/#AAA", "AAA:Resource");
        resource.appendChild(doc.createTextNode("Resource element defines the target resource\n"));
        root.appendChild(resource);
        root.appendChild(doc.createTextNode("\n"));

        Element action = doc.createElementNS("http://www.aaauthreach.org/ns/#AAA", "AAA:Action");
        action.appendChild(doc.createTextNode("Action element will contain the requested action\n"));
        root.appendChild(action);
        root.appendChild(doc.createTextNode("\n"));
        doc.appendChild(doc.createComment(" Comment after "));

        // end of document creation part
        // save echo file before signing
        saveDOMdoc(doc, savefile);
        System.out.println("\nWrote doc before signing to " + savefile);

        return doc;
    }
    public static Document encryptDocSymmetric (Document document, Key skek) throws Exception {

    	/* Document document
    	 * Key skek - symmetric key wrapping key
    	 * Key sdek - symmetric data encryption key
    	 * String algodataURI
    	 */
        //Method/Algorithm for Data encryption key
        String algodataURI = XMLCipher.AES_128;
        String algoskekURI = XMLCipher.TRIPLEDES_KeyWrap;

        //Type/Algorithm for Data encryption key
  	   	String jceAlgoData = "AES";
        Key sdek = GenerateDataEncryptionKey(jceAlgoData);

        XMLCipher keyCipher = XMLCipher.getInstance(algoskekURI);
        keyCipher.init(XMLCipher.WRAP_MODE, skek);
        EncryptedKey encryptedKey = keyCipher.encryptKey(document, sdek);
            
        /*
         * Let us encrypt the contents of the document element.
         */
        Element rootelm = document.getDocumentElement();
        //Element elem2encr = document.getElementById("subject");
        //the above getElementById() doesn't because of some unknown reason (?)
        //Element elem2encr = (Element) document.getElementsByTagNameNS("http://www.aaauthreach.org/ns/#AAA", "Subject").item(0);
        Element elem2encr = rootelm;
        
        if (elem2encr == null)
        {System.out.print("\n###this element will be encrypted:\n");} else {
        	System.out.print("\n###element to encrypt is not null\n");}
        
        //algodataURI = XMLCipher.AES_128;
        //printDOMdoc(document);
		printDOMelem(elem2encr);
        //printDOMdoc((Document)node2encr);

        XMLCipher xmlCipher = XMLCipher.getInstance(algodataURI);
        xmlCipher.init(XMLCipher.ENCRYPT_MODE, sdek);

        /*
         * Setting keyinfo inside the encrypted data being prepared.
         */
        EncryptedData encryptedData = xmlCipher.getEncryptedData();
        KeyInfo keyInfo = new KeyInfo(document);
        keyInfo.add(encryptedKey);
        encryptedData.setKeyInfo(keyInfo);
    	
        /*
         * doFinal -
         * "true" below indicates that we want to encrypt element's content
         * and not the element itself. Also, the doFinal method would
         * modify the document by replacing the EncrypteData element
         * for the data to be encrypted.
         */
        xmlCipher.doFinal(document, elem2encr, true);

    	/*
         * Output the document containing the encrypted information into
         * a file.
         */
        //outputDocToFile(document, docencrsave);
        
         return document;    	
    }

    public static Document encryptDocSymmetric (Document document, Element elem2encr,
    		Key skek) throws Exception {

    	/* Document - document
    	 * elem2encr - element to encrypt of the context document
    	 * Key skek - symmetric key wrapping key
    	 */
        //Method/Algorithm for Data encryption key
        String algodataURI = XMLCipher.AES_128;
        String algoskekURI = XMLCipher.TRIPLEDES_KeyWrap;

        //Type/Algorithm for Data encryption key
  	   	String jceAlgoData = "AES";
        Key sdek = GenerateDataEncryptionKey(jceAlgoData);

        XMLCipher keyCipher = XMLCipher.getInstance(algoskekURI);
        keyCipher.init(XMLCipher.WRAP_MODE, skek);
        EncryptedKey encryptedKey = keyCipher.encryptKey(document, sdek);
                
        if (elem2encr == null)
        {System.out.print("\n###this element will be encrypted:\n");} else {
        	System.out.print("\n###element to encrypt is not null\n");}
        
        //printDOMdoc(document);
		printDOMelem(elem2encr);

        XMLCipher xmlCipher = XMLCipher.getInstance(algodataURI);
        xmlCipher.init(XMLCipher.ENCRYPT_MODE, sdek);

        /*
         * Setting keyinfo inside the encrypted data being prepared.
         */
        EncryptedData encryptedData = xmlCipher.getEncryptedData();
        KeyInfo keyInfo = new KeyInfo(document);
        keyInfo.add(encryptedKey);
        encryptedData.setKeyInfo(keyInfo);
    	
        /*
         * doFinal -
         * "true" below indicates that we want to encrypt element's content
         * and not the element itself. Also, the doFinal method would
         * modify the document by replacing the EncrypteData element
         * for the data to be encrypted.
         */
        xmlCipher.doFinal(document, elem2encr, true);

    	/*
         * Output the document containing the encrypted information into
         * a file.
         */
        //outputDocToFile(document, docencrsave);
        
         return document;    	
    }

    public static Document encryptDocPublic (Document document, Key pubkek) throws Exception {

    	/* Document document
    	 * Key pubkek - public key wrapping key
    	 * Key sdek - symmetric data encryption key
    	 * String algodataURI
    	 * 
    	 */
        //Method/Algorithm for Data encryption key
        String algodataURI = XMLCipher.AES_128;

        //Type/Algorithm for Data encryption key
  	   	String jceAlgoData = "AES";
        Key sdek = GenerateDataEncryptionKey(jceAlgoData);

	    System.out.print("\n###Public key encryption key: \n" + pubkek.toString() + "\n");

        String algopkekURI = XMLCipher.RSA_v1dot5;

            XMLCipher keyCipher = XMLCipher.getInstance(algopkekURI);
            keyCipher.init(XMLCipher.WRAP_MODE, pubkek);
            EncryptedKey encryptedKey = keyCipher.encryptKey(document, sdek);
        /*
         * Let us encrypt the contents of the document element.
         */
        Element rootElement = document.getDocumentElement();

        //algodataURI = XMLCipher.AES_128;
	    System.out.print("\n###Symmetric data encryption key: " + sdek.toString() + "\n");

        XMLCipher xmlCipher = XMLCipher.getInstance(algodataURI);
        xmlCipher.init(XMLCipher.ENCRYPT_MODE, sdek);

        /*
         * Setting keyinfo inside the encrypted data being prepared.
         */
        EncryptedData encryptedData = xmlCipher.getEncryptedData();
        KeyInfo keyInfo = new KeyInfo(document);
        keyInfo.add(encryptedKey);
        encryptedData.setKeyInfo(keyInfo);
    	
        /*
         * doFinal -
         * "true" below indicates that we want to encrypt element's content
         * and not the element itself. Also, the doFinal method would
         * modify the document by replacing the EncrypteData element
         * for the data to be encrypted.
         */
        xmlCipher.doFinal(document, rootElement, true);
    	
    	/*
         * Output the document containing the encrypted information into
         * a file.
         */
        //outputDocToFile(document, docencrsave);
        
         return document;    	
    }

    private static SecretKey GenerateAndStoreKeyEncryptionKey(String jceAlgorithmName, String kekfname)
        throws Exception {

        String kekpath = "data/keystore/xmlsec/symkeystore/" + kekfname;
    	//String jceAlgorithmName = "DESede";
        KeyGenerator keyGenerator =
            KeyGenerator.getInstance(jceAlgorithmName);
        SecretKey kek = keyGenerator.generateKey();

        byte[] keyBytes = kek.getEncoded();
        File kekFile = new File(kekpath);
        FileOutputStream f = new FileOutputStream(kekFile);
        f.write(keyBytes);
        f.close();
        System.out.println(
            "Key encryption key stored in " + kekFile.toURL().toString());

        return kek;
    }

    private static SecretKey GenerateDataEncryptionKey(String jceAlgorithmName) throws Exception {

        //String jceAlgorithmName = "AES";
        KeyGenerator keyGenerator =
            KeyGenerator.getInstance(jceAlgorithmName);
        keyGenerator.init(128);
        return keyGenerator.generateKey();
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
            "Wrote document containing encrypted data to " +
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
 	
 	public static void printDOMelem (org.w3c.dom.Element elem) throws Exception {
        // print DOM doc
        ByteArrayOutputStream f = new ByteArrayOutputStream();
        XMLUtils.outputDOMc14nWithComments((Node)elem, f);
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
 	
    public static void main(String unused[]) throws Exception {

  		//File signedFile = new File("encrypted-" + savefile);
      	String inputFile = "aaareq01nons.xml";

  		Document document = createSampleDoc();
  		//printDOMdoc(document);

  		//Receive parameters for the pubkey keystore
  	  	String keyalias = "cnl01";
  	   	List checkconfsec = new ArrayList();
  	   	List keyset = KeyStoreConfig.getConfigKeys(keyalias);
  	   	Key privkey = getPrivKey (keyset);
  	   	Key pubkey = getPublicKey (keyset);
        Key pubkek = pubkey;
  	   	
        //Type/Algorithm for Data encryption key
  	   	String jceAlgoData = "AES";
        Key symmetricKey = GenerateDataEncryptionKey(jceAlgoData);
        Key sdek = symmetricKey;
           	
        //Type/Algorithm for Key encryption key
  	   	String jceAlgoKey = "DESede";
        
        //Method/Algorithm for Data encryption key
        String algodataURI = XMLCipher.AES_128;
        
  	   	//Method/Algorithm for encryption Data encryption key
        String algokekURI = XMLCipher.TRIPLEDES_KeyWrap;
        
        ////////// initial debug block
        // Note: this block also changes the document content 
        /*Document docext0 = readFileToDOM (inputFile); 
	    Key skek0 = GenerateAndStoreKeyEncryptionKey(jceAlgoKey, "kek1");
		Document docencr0 = encryptDocSymmetric (document, skek0, sdek, algodataURI);
		printDOMdoc(docencr0);
		printDOMdoc(document);
        */
       	try {   	
       	   	System.out.println("Running Examples for XML Encryption types for AAARequest.\n" +
       	   			"Implements XMLEnc recommended procedure: \n" +
       	   			"(1) data are encrypted with the symmetric instantly generated key (dek - AES_128), and \n" +
       	   			"(2) this dek is encrypted with another shared symmetric key (kek) or with repicient's public key, \n" +
       	   			"(3) encrypted kek is included into the <xenc:EncryptedData>/<ds:KeyInfo> element ");
       		System.out.println("Select Encryption option ( \n" + 
       				"1 - Create and encrypt doc (with the symmetric dek and kek)\n" + 
       				"2 - Create and encrypt an element <Subject> of the context doc (with the symmetric dek and kek)\n" +  
       				"3 - Read and encrypt ext doc (with the symmetric dek and kek)\n" + 
       				"4 - Create and encrypt doc (with the symmetric dek and asymmentric/PKI public kek)\n" + 
       				"5 - Read and encrypt an element <Subject> of ext doc (with the symmetric dek and kek)" + 
					"");
       		int s = HelpersReadWrite.readStdinInt();			
       		//printKeyInfo (keyalias); 
       		switch(s) {
       			case 1: { 
       		        Key skek1 = GenerateAndStoreKeyEncryptionKey(jceAlgoKey, "kek1");
       				Document docencr = encryptDocSymmetric (document, skek1);
       				outputDocToFile(docencr, "enc1sym-doc.xml"); 
       				//printDOMdoc(docencr);
       				return;}
       			case 2: {
       				Key skek2 = GenerateAndStoreKeyEncryptionKey(jceAlgoKey, "kek2");
       		        Element elem2encr = (Element) document.getElementsByTagNameNS("http://www.aaauthreach.org/ns/#AAA", "Subject").item(0);
       		        //Element elem2encr = (Element) document.getElementsByTagNameNS("http://www.aaauthreach.org/ns/#AAA", "Action").item(0);
       				Document docencr = encryptDocSymmetric (document, elem2encr, skek2);
       				outputDocToFile(docencr, "enc2symelm-doc.xml"); 
       				//printDOMdoc(docencr);
       				return;}
       			case 3: { Document docext = readFileToDOM (inputFile); 
       				Key skek3 = GenerateAndStoreKeyEncryptionKey(jceAlgoKey, "kek3");
       				Document docencr = encryptDocSymmetric (docext, skek3);
       				outputDocToFile(docencr, ("enc3rypted-" + inputFile)); 
       				//printDOMdoc(docencr);
       				return;}
       			case 4: {
       				Document docencr = encryptDocPublic (document, pubkek);
       				outputDocToFile(docencr, "enc4public-doc.xml"); 
       				//printDOMdoc(docencr);
       				return;}
       			case 5: { Document docext = readFileToDOM (inputFile); 
   					Key skek5 = GenerateAndStoreKeyEncryptionKey(jceAlgoKey, "kek5");
       		        Element elem2encr = (Element) docext.getElementsByTagNameNS(
       		        		"urn:oasis:names:tc:xacml:1.0:context",
       		        		"Subject").item(0);
       		        if (elem2encr == null)
       		        {System.out.print("\n###this element will be encrypted:\n");} else {
       		        	System.out.print("\n###element to encrypt is not null\n");}
       				//printDOMelem(elem2encr);
       		        Document docencr = encryptDocSymmetric (docext, elem2encr, skek5);
   					outputDocToFile(docencr, ("enc5cryptedelm-" + inputFile)); 
   					//printDOMdoc(docencr);
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

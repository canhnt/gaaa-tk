/*
 * Copyright  2004-2005 AIRG.
 *
 *
 */
package org.aaaarch.gaaapi.test.xmlsec;

import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.xml.transform.*;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.params.XPathContainer;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

//import org.aaaarch.msg.xacml.context.AAARequestType;
import org.aaaarch.config.KeyStoreConfig;
//import org.aaaarch.schema.xml.XmlException;
import org.aaaarch.utils.*;

/**
 *
 * @author $Author: demch $
 */
public class Example03SignatureInputTypes {

   /** {@link org.apache.commons.logging} logging facility */
   // static org.apache.commons.logging.Log log = 
   //     org.apache.commons.logging.LogFactory.getLog(CreateSignature.class.getName());
	
 	public static org.w3c.dom.Document signDOMDoc (List keyset, org.w3c.dom.Document doc) throws Exception {

 		File signedFile = new File("signed-test03doc.xml");

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
  	    
        // start xml document processing part
        //org.w3c.dom.Document doc is already received

        org.w3c.dom.Element root = doc.getDocumentElement();

        //Create an XML Signature object from the document, BaseURI and
        //signature algorithm (in this case RSA)
        String BaseURI = signedFile.toURL().toString();
        XMLSignature sig = new XMLSignature(doc, BaseURI,
                                            XMLSignature.ALGO_ID_SIGNATURE_RSA);

        //Append the signature element to the root element before signing because
        //for an enveloped signature.
        root.appendChild(sig.getElement());

        sig.getSignedInfo()
           .addResourceResolver(new org.apache.xml.security.samples.utils.resolver
              .OfflineResolver());

        {
            //create the transforms object for the Document/Reference
            Transforms transforms = new Transforms(doc);
            transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
            transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
            sig.addDocument("#subject", transforms, Constants.ALGO_ID_DIGEST_SHA1);
            //sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);
            //sig.addDocument("#xpointer(id('subject'))", transforms, Constants.ALGO_ID_DIGEST_SHA1);
          }
        
        {
           //Add the KeyInfo containing the X.509 PKC of the used the private key
           X509Certificate cert =
              (X509Certificate) ks.getCertificate(certificateAlias);
           sig.addKeyInfo(cert);
           sig.addKeyInfo(cert.getPublicKey());

           // Actual signing
           sig.sign(privateKey);
        }

      FileOutputStream f = new FileOutputStream(signedFile);
      XMLUtils.outputDOMc14nWithComments(doc, f);
      f.close();
      System.out.println("\nDOM doc is signed and saved in echo " + BaseURI);
      return doc;
 	}   

 	////////////////// Receive XML string Document and Sign
 	public static String signStringDoc (List keyset, String docstr) throws Exception {

 		File signedFile = new File("signed-test03doc.xml");

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
  	    
        // start xml document processing part
        javax.xml.parsers.DocumentBuilderFactory dbf =
           javax.xml.parsers.DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
        //org.w3c.dom.Document doc = db.newDocument();

        //////////////// reading document and getting the root element
        org.w3c.dom.Document doc = db.parse( new StringBufferInputStream (docstr) ); 
        org.w3c.dom.Node root = doc.getDocumentElement();

        //Create an XML Signature object from the document, BaseURI and
        //signature algorithm (in this case RSA)
        String BaseURI = signedFile.toURL().toString();
        XMLSignature sig = new XMLSignature(doc, BaseURI,
                                            XMLSignature.ALGO_ID_SIGNATURE_RSA);

        //Append the signature element to the root element before signing because
        //for an enveloped signature.
        root.appendChild(sig.getElement());

        sig.getSignedInfo()
           .addResourceResolver(new org.apache.xml.security.samples.utils.resolver
              .OfflineResolver());

        {
            //create the transforms object for the Document/Reference
            Transforms transforms = new Transforms(doc);
            transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
            transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
            sig.addDocument("#subject", transforms, Constants.ALGO_ID_DIGEST_SHA1);
            //sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);
            //sig.addDocument("#xpointer(id('subject'))", transforms, Constants.ALGO_ID_DIGEST_SHA1);
          }
        
        {
           //Add the KeyInfo containing the X.509 PKC of the used the private key
           X509Certificate cert =
              (X509Certificate) ks.getCertificate(certificateAlias);
           sig.addKeyInfo(cert);
           sig.addKeyInfo(cert.getPublicKey());

           // Actual signing
           sig.sign(privateKey);
        }

      //converting signed DOM doc to output String doc
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      XMLUtils.outputDOMc14nWithComments(doc, bos);
      String sigdocstr = bos.toString();
      bos.close();

      // writing to echo file "signed-doc.xml"
      FileOutputStream f = new FileOutputStream(signedFile);
      XMLUtils.outputDOMc14nWithComments(doc, f);
      f.close();
      System.out.println("\nString doc is signed and saved in echo " + BaseURI);
      
      return sigdocstr;
  	}   
 	
 	////////////////// Read and sign document from file
 	
 	public static void readAndSignFile (List keyset, String finput) throws Exception {

  		File signedFile = new File("signed-" + finput);
        //File echoFile = new File("echo-" + finput);
        String echoFile = "signed-test03doc.xml";
        
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
         //System.out.print("\n###Private key: \n" + privateKey.toString());
  	    
        // start xml document processing part
        javax.xml.parsers.DocumentBuilderFactory dbf =
           javax.xml.parsers.DocumentBuilderFactory.newInstance();

        //XML Signature needs to be namespace aware
        dbf.setNamespaceAware(true);

        javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
        //org.w3c.dom.Document docnew = db.newDocument();

        // reading document
        org.w3c.dom.Document doc = db.parse(finput);

        // defining root element
        org.w3c.dom.Element root = doc.getDocumentElement();

        //The BaseURI is the URI that's used to prepend to relative URIs
        String BaseURI = signedFile.toURL().toString();

        //Create an XML Signature object from the document, BaseURI and
        //signature algorithm (in this case RSA)
        XMLSignature sig = new XMLSignature(doc, BaseURI,
                                            XMLSignature.ALGO_ID_SIGNATURE_RSA);

        //Append the signature element to the root element before signing because
        //this is going to be an enveloped signature.
        //This means the signature is going to be enveloped by the document.
        //Two other possible forms are enveloping where the document is inside the
        //signature and detached where they are seperate.
        //Note that they can be mixed in 1 signature with seperate references as
        //shown below.
        root.appendChild(sig.getElement());

        sig.getSignedInfo()
           .addResourceResolver(new org.apache.xml.security.samples.utils.resolver
              .OfflineResolver());

        {/*
           //create the transforms object for the Document/Reference
           Transforms transforms = new Transforms(doc);

           //First we have to strip away the signature element (it's not part of the
           //signature calculations). The enveloped transform can be used for this.
           transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
           //Part of the signature element needs to be canonicalized. It is a kind
           //of normalizing algorithm for XML. For more information please take a
           //look at the W3C XML Digital Signature webpage.
           transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
           //Add the above Document/Reference

           sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);
           //sig.addDocument("#xpointer(id('subject'))", transforms, Constants.ALGO_ID_DIGEST_SHA1);
           //sig.addDocument("#subject", transforms, Constants.ALGO_ID_DIGEST_SHA1);
         */}

        {
            //create the transforms object for the Document/Reference
            Transforms transforms = new Transforms(doc);
            transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
            transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
            sig.addDocument("#subject", transforms, Constants.ALGO_ID_DIGEST_SHA1);
          }
        
        {
           //Add in the KeyInfo for the certificate that we used the private key of
           X509Certificate cert =
              (X509Certificate) ks.getCertificate(certificateAlias);

           //System.out.print("\n### X.509 content: \n" + cert.toString()); //***  
           
           sig.addKeyInfo(cert);
           sig.addKeyInfo(cert.getPublicKey());

           // Actual signing
           System.out.println("Start signing ext/file doc");
           sig.sign(privateKey);
           System.out.println("Finished signing ext doc");
        }

////////////////  Another signature       
        
        XMLSignature sig1 = new XMLSignature(doc, BaseURI,
                XMLSignature.ALGO_ID_SIGNATURE_RSA);
        sig1.setId("sig1");
        root.appendChild(sig1.getElement());

        sig1.getSignedInfo()
			.addResourceResolver(new org.apache.xml.security.samples.utils.resolver
					.OfflineResolver());
        
        {
        	//create the transforms object for the Document/Reference
        	Transforms transforms = new Transforms(doc);
        	transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        	transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
        	//sig1.addDocument("#subject", transforms, Constants.ALGO_ID_DIGEST_SHA1);
            //sig1.addDocument("#xpointer(id('subject'))", transforms, Constants.ALGO_ID_DIGEST_SHA1);
            //sig1.addDocument("#xpointer(element(/1))", transforms, Constants.ALGO_ID_DIGEST_SHA1);
            //#xpointer(here()/ancestor::slide[1]/preceding::slide[1])
        }

        {
            // sign the message with Subject and Resource and no signature
            String xp1 = "not(ancestor-or-self::ds:Signature)" + "\n"
                      + " and (" + "\n"
                      + "    (ancestor-or-self::node() = /AAARequest/Subject) " + "\n"
                      + " or (ancestor-or-self::node() = /AAARequest/Resource) " + "\n"
                      //+ " or (self::node() = /contract) " + "\n"
                      //+ " or ((parent::node() = /contract) and (self::text()))" + "\n"
                      + ")";

            // sign the whole contract and no signature but the first
            //String xp2 = "not(ancestor-or-self::ds:Signature)" + "\n"
            //           + " or ancestor-or-self::ds:Signature[@Id='" + id1 + "']";

            Transforms transforms = new Transforms(doc);
             XPathContainer xpath = new XPathContainer(doc);

             xpath.setXPathNamespaceContext("ds", Constants.SignatureSpecNS);
             xpath.setXPath("\n" + xp1 + "\n");
             transforms.addTransform(Transforms.TRANSFORM_XPATH,
                                     xpath.getElementPlusReturns());
             sig1.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);
        }
        
        {
         //Add in the KeyInfo for the certificate that we used the private key of
         X509Certificate cert = (X509Certificate) ks.getCertificate(certificateAlias);
         sig1.addKeyInfo(cert);
         sig1.addKeyInfo(cert.getPublicKey());
        	
        // Actual signing
        System.out.println("Start 2nd signing ext doc");
        sig1.sign(privateKey);
        System.out.println("Finished 2nd signing ext doc");
        }
        
      FileOutputStream f = new FileOutputStream(signedFile);
      XMLUtils.outputDOMc14nWithComments(doc, f);
      f.close();
      System.out.println("Wrote signature to " + BaseURI);
      // echo file
      saveDOMdoc(doc, echoFile);
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
         //System.out.print("\n###Private key: \n" + privateKey.toString());
        return privateKey;
	
	} 

 	public static org.w3c.dom.Document readFileToDOM (String filename) throws Exception {
        // start xml document processing part
        javax.xml.parsers.DocumentBuilderFactory dbf =
           javax.xml.parsers.DocumentBuilderFactory.newInstance();

        //XML Signature needs to be namespace aware
        dbf.setNamespaceAware(true);
        javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
        // reading document
        org.w3c.dom.Document doc = db.parse(filename);
        //System.out.println("\nFile is now a DOM doc \n" );
        //printDOMdoc(doc);
        return doc;
 	}	

 	public static String readFileToString (String filename) throws Exception {
        // start xml document processing part
        javax.xml.parsers.DocumentBuilderFactory dbf =
           javax.xml.parsers.DocumentBuilderFactory.newInstance();

        //XML Signature needs to be namespace aware
        dbf.setNamespaceAware(true);

        javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
        //org.w3c.dom.Document docnew = db.newDocument();

        // reading document
        org.w3c.dom.Document doc = db.parse(filename);
        //printDOMdoc(doc);

        ByteArrayOutputStream f = new ByteArrayOutputStream();
        XMLUtils.outputDOMc14nWithComments(doc, f);
        String docstr = f.toString();
        f.close();
        return docstr;
 	}	

 	public static org.w3c.dom.Document readStringToDOM (String docstr) throws Exception {
        // start xml document processing part
        javax.xml.parsers.DocumentBuilderFactory dbf =
           javax.xml.parsers.DocumentBuilderFactory.newInstance();

        //XML Signature needs to be namespace aware
        dbf.setNamespaceAware(true);
        javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
        // reading document
        org.w3c.dom.Document doc = db.parse( new StringBufferInputStream (docstr) );
        //System.out.println("\nstring doc is now a DOM doc \n" );
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
        //System.out.println("\n" + f.toString());
        System.out.print("\n" + f);
 	}
 	
 	public static void saveDOMdoc (org.w3c.dom.Document doc, String filename) throws Exception {
        // save file from DOM doc
        FileOutputStream f = new FileOutputStream(filename);
        XMLUtils.outputDOMc14nWithComments(doc, f);
        f.close();
        //System.out.println("Wrote echo DOM doc to " + filename);
 	}
 	
   static {
      org.apache.xml.security.Init.init();
   }
   
   public static void main(String args[]) throws Exception {
      Constants.setSignatureSpecNSprefix("ds"); //# think about adding "ds:" prefix

      //Receive parameters for the keystore
  	String keyalias = "cnl01";
  	String infile = "aaareq01nons.xml";
   	List checkconfsec = new ArrayList();
   	List keyset = KeyStoreConfig.getConfigKeys(keyalias);

   	// define part of the document to be signed
   	// define parts of the document to be signed
   	String uri2sign0 = ""; 
   	String uri2sign1 = "#subject"; 
   	String uri2sign2 = "#xpointer(id('subject'))";
    String xp1 = "not(ancestor-or-self::ds:Signature)" + "\n"
    + " and (" + "\n"
    + "    (ancestor-or-self::node() = /AAARequest/Subject) " + "\n"
    + " or (ancestor-or-self::node() = /AAARequest/Resource) " + "\n"
    //+ " or (self::node() = /AAARequest) " + "\n"
    //+ " or ((parent::node() = /AAARequest) and (self::text()))" + "\n"
    + ")";

    // sign the whole contract and no signature but the first
    //String xp2 = "not(ancestor-or-self::ds:Signature)" + "\n"
    //           + " or ancestor-or-self::ds:Signature[@Id='" + id1 + "']";

    // components test block
	/*
    System.out.println("Initial test block\n");
	System.out.println("\nread file and print DOM doc\n");
    org.w3c.dom.Document doc1 = readFileToDOM (infile);
    printDOMdoc(doc1);
	System.out.println("\nread file and print String doc\n");
	String docstr = readFileToString (infile);
	System.out.print(docstr);
	System.out.println("\nread String doc and print DOM doc\n");
	org.w3c.dom.Document doc2 = readStringToDOM(docstr);
    printDOMdoc(doc1);
	*/
   	// call methods to read and sign external document

   	try {   	
	System.out.println("\nRunning Examples for XML Signature for different input types");
	System.out.println("Select Signature option ( " + 
			//"0 - ENVELOPED for whole document, e.g. <ds:Reference URI=\"\">\n" + 
			"1 - sign file (multiple signatures), " +
			"2 - sign DOM, " +
			"3 - sign string doc )");

	int s = HelpersReadWrite.readStdinInt();			
	//printKeyInfo (keyalias); 
	switch(s) {
		case 0: {}
		case 1: {readAndSignFile (keyset, infile);  return;}
		case 2: {printDOMdoc(signDOMDoc (keyset, readFileToDOM(infile))); return;}
		//case 3: {signStringDoc (keyset, readFileToString(inputFile)); return;}
		case 3: {System.out.print(signStringDoc(keyset, readFileToString(infile))); return;}
	} 
	System.out.println("OK");
	System.exit(0);
   	} catch (Exception e) {
   		e.printStackTrace();
   		System.exit(1);
   		}
   }
}

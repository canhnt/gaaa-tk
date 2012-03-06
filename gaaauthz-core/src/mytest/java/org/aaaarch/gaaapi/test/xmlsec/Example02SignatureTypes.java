/*
 * Copyright  2004-2005 AIRG.
 *
 *
 */
package org.aaaarch.gaaapi.test.xmlsec;



import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.params.XPathContainer;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Element;

import org.aaaarch.config.KeyStoreConfig;
import org.aaaarch.utils.*;

/**
 *
 *
 * @author $Author: demch $
 */
public class Example02SignatureTypes {

   /** {@link org.apache.commons.logging} logging facility */
   // static org.apache.commons.logging.Log log = 
   //     org.apache.commons.logging.LogFactory.getLog(CreateSignature.class.getName());
 	
/////////////// Create a simple document and sign with the Enveloped Signature

 	public static void CreateAndSignDoc (List keyset, String uri2sign, String xpath2sign) throws Exception {

 	    String savefile = "aaareq02test.xml";
  		File signedFile = new File("signed-" + savefile);
        
  	    String keystoreType = (String) keyset.get(0);
  	    String keystoreFile = (String) keyset.get(1);
  	    String keystorePass = (String) keyset.get(2);
  	    String privateKeyAlias = (String) keyset.get(3);
  	    String privateKeyPass = (String) keyset.get(4);
  	    String certificateAlias = (String) keyset.get(5);

        //J+
        KeyStore ks = KeyStore.getInstance(keystoreType);
        FileInputStream fis = new FileInputStream(keystoreFile);

        ////FileOutputStream fus = new FileOutputStream(outFile);
        ////System.out.print(fis.toString());
        
        //load the keystore
        ks.load(fis, keystorePass.toCharArray());

        //get the private key for signing.
        PrivateKey privateKey = (PrivateKey) ks.getKey(privateKeyAlias,
                                               privateKeyPass.toCharArray());
         //System.out.print("\n###Private key: \n" + privateKey.toString()); //***
        
        
      //Build a sample document. It will look something like:
      /*
       <!-- Comment before -->
      <AAA:AAARequest xmlns:AAA="http://www.aaauthreach.org/ns/#AAA" xmlns:cnl="http://example.org/#cnl" attr1="test1" attr2="test2" cnl:attr1="CNL2 test">
      <AAA:Subject Id="subject">Subject will contain SubjectID, AuthN token and Subject attributes
      </AAA:Subject>
		<AAA:Resource>Resource element defines target resource
		</AAA:Resource>
		<AAA:Action>Action element will contain requested action
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
      
      //The BaseURI is the URI that's used to prepend to relative URIs
      String BaseURI = signedFile.toURL().toString();

      //Create an XML Signature object from the document, BaseURI and
      //signature algorithm (in this case DSA)
      XMLSignature sig = new XMLSignature(doc, BaseURI,
                                          XMLSignature.ALGO_ID_SIGNATURE_RSA);

      //Append the signature element to the root element before signing because
      //this is going to be an enveloped signature.
      //This means the signature is going to be enveloped by the document.
      //Two other possible forms are enveloping where the document is inside the
      //signature and detached where they are separate.
      //Note that they can be mixed in 1 signature with separate references as
      //shown below.
      root.appendChild(sig.getElement());
      sig.getSignedInfo()
         .addResourceResolver(new org.apache.xml.security.samples.utils.resolver
            .OfflineResolver());

      if (uri2sign != null) 
      {
        //String uri22sign = ""; 
        //String uri22sign = "#subject"; 
        //String uri22sign = "#subject"; 
      	//String uri2sign2 = "#xpointer(id('subject'))";
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
         sig.addDocument(uri2sign, transforms, Constants.ALGO_ID_DIGEST_SHA1);
         //sig.addDocument(uri22sign, transforms, Constants.ALGO_ID_DIGEST_SHA1);
         
      } else
      {
        // sign the message with Subject and no signature
        //String xp1 = "not(ancestor-or-self::ds:Signature)" + "\n"
        //          + "    (ancestor-or-self::node() = /AAARequest/Subject)";

        Transforms transforms = new Transforms(doc);
         XPathContainer xpath = new XPathContainer(doc);

         xpath.setXPathNamespaceContext("ds", Constants.SignatureSpecNS);
         xpath.setXPath("\n" + xpath2sign + "\n");
         transforms.addTransform(Transforms.TRANSFORM_XPATH,
                                 xpath.getElementPlusReturns());
         sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);
      }

      	
      {
         //Add in 2 external URIs. This is a detached Reference.
         //
         // When sign() is called, two network connections are made. -- well,
         // not really, as we use the OfflineResolver which acts as a proxy for
         // these two resouces ;-))
         //
         //sig.addDocument("http://www.w3.org/TR/xml-stylesheet");
         //sig.addDocument("http://www.nue.et-inf.uni-siegen.de/index.html");
      }

      {
         //Add in the KeyInfo for the certificate that we used the private key of
         X509Certificate cert =
            (X509Certificate) ks.getCertificate(certificateAlias);

         //System.out.print("\n### X.509 content: \n" + cert.toString()); //***  
         
         sig.addKeyInfo(cert);
         sig.addKeyInfo(cert.getPublicKey());
         System.out.println("Start signing");
         sig.sign(privateKey);
         System.out.println("Finished signing");
      
      }

      FileOutputStream f = new FileOutputStream(signedFile);
      
      XMLUtils.outputDOMc14nWithComments(doc, f);
      f.close();
      System.out.println("Wrote signature to " + BaseURI);
      //System.out.print(f1);
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

 	
 	public static X509Certificate getCert (List keyset) throws Exception {

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
        //Add in the KeyInfo for the certificate that we used the private key of
        X509Certificate cert =
           (X509Certificate) ks.getCertificate(certificateAlias);

        //System.out.print("\n### X.509 content: \n" + cert.toString()); //***  
        
        PublicKey pubbkey = cert.getPublicKey();
        
        return cert;
	        
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
 	
 	static {
      org.apache.xml.security.Init.init();
   }
   
   /**
    * Method main
    * @param interactive
    * @throws Exception
    */
   public static void main(String args[]) throws Exception {
      Constants.setSignatureSpecNSprefix("ds"); //# think about adding "ds:" prefix

      //Receive parameters for the keystore
  	String keyalias = "cnl01";
  	String inputFile = "x-output/uc6-assertion01-signed.xml";
   	//List checkconfsec = new ArrayList();
   	List keyset = KeyStoreConfig.getConfigKeys(keyalias);

   	// read file to DOM document
   	org.w3c.dom.Document doc2sign = readFileToDOM (inputFile);

    // print echo file after parsing
   	// printDOMdoc(doc2sign);
   	
   	// uri for signed elements
   	String uri2sign1 = "#subject"; 
   	String uri2sign2 = "#xpointer(id('subject'))";
   	String xpath2sign1 = "not(ancestor-or-self::ds:Signature) \n" +
						"and (ancestor-or-self::node() = /AAARequest/Subject)";
   	
   	// call methods to read and sign external document

   	try {   	
   	System.out.println("Running Examples for XML Signature types for AAARequest");
	System.out.println("Select Signature option ( \n" + 
			"0 - Create and sign whole document with an ENVELOPED Signaturee.g. <ds:Reference URI=\"\">\n" + 
			"1 - ENVELOPED for element by Id/ID, e.g. URI=\"#subject\"\n" + 
			"2 - ENVELOPED for element by Id/ID, e.g. URI=\"#xpointer(id('subject'))\"\n" +
			"3 - ENVELOPED for element with XPath TRANSFORM, e.g. \n" +
			"    XPath = not(ancestor-or-self::ds:Signature) \n" +
			"    and (ancestor-or-self::node() = /AAARequest/Subject)");
	int s = HelpersReadWrite.readStdinInt();			
	printKeyInfo (keyalias); 
	switch(s) {
		case 0: {CreateAndSignDoc (keyset, "", null);  return;}
		case 1: {CreateAndSignDoc (keyset, uri2sign1, null);  return;}
		case 2: {CreateAndSignDoc (keyset, uri2sign2, null);  return;}
		case 3: {CreateAndSignDoc (keyset, null, xpath2sign1); return;}
	}
	System.out.println("OK");
	System.exit(0);
   	} catch (Exception e) {
   		e.printStackTrace();
   		System.exit(1);
   		}
   }
}

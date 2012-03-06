/*
 * Created on Nov 28, 2004
 *
 * TODO To change the template for this generated file go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
package org.aaaarch.gaaapi.test;

import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.xml.transform.*;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;

import org.aaaarch.config.KeyStoreConfig;
import org.aaaarch.impl.signature.CreateSignature;
import org.aaaarch.utils.HelpersReadWrite;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.params.XPathContainer;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * @author demch
 * 
 * TODO To change the template for this generated type comment go to Window -
 * Preferences - Java - Code Style - Code Templates
 */
public class TestCreateSignature {
	public static void printKeyInfo(String keyalias) throws Exception {
		List checkconfsec = new ArrayList();

		checkconfsec = KeyStoreConfig.getConfigKeys(keyalias);

		String keystoreType = (String) checkconfsec.get(0);
		String keystoreFile = (String) checkconfsec.get(1);
		String keystorePass = (String) checkconfsec.get(2);
		String privateKeyAlias = (String) checkconfsec.get(3);
		String privateKeyPass = (String) checkconfsec.get(4);
		String certificateAlias = (String) checkconfsec.get(5);
		//

		System.out.print("\n###Echo Key information\n" + "keystoreType="
				+ keystoreType + "\n" + "keystoreFile=" + keystoreFile + "\n"
				+ "keystorePass=" + keystorePass + "\n" + "privateKeyAlias="
				+ privateKeyAlias + "\n" + "privateKeyPass=" + privateKeyPass
				+ "\n" + "certificateAlias=" + certificateAlias + "\n\n");
	}

	public static PrivateKey getPrivKey(List keyset) throws Exception {

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

	public static org.w3c.dom.Document readFileToDOM(String filename)
			throws Exception {
		// start xml document processing part
		javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory
				.newInstance();

		//XML Signature needs to be namespace aware
		dbf.setNamespaceAware(true);
		javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
		// reading document
		org.w3c.dom.Document doc = db.parse(filename);
		//System.out.println("\nFile is now a DOM doc \n" );
		//printDOMdoc(doc);
		return doc;
	}

	public static String readFileToString(String filename) throws Exception {

		//String fi = "aaareq01nons.xml";
		//System.out.println("\necho: file to read " + fi);

		// start xml document processing part
		javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory
				.newInstance();

		//XML Signature needs to be namespace aware
		dbf.setNamespaceAware(true);

		javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
		//org.w3c.dom.Document docnew = db.newDocument();

		// reading document
		org.w3c.dom.Document doc = db.parse(filename);
		//org.w3c.dom.Document doc = db.parse(fi);
		//printDOMdoc(doc);
		ByteArrayOutputStream f = new ByteArrayOutputStream();
		XMLUtils.outputDOMc14nWithComments(doc, f);
		String docstr = f.toString();
		f.close();
		//printDOMdoc(doc);
		//System.out.println("\necho: readFileToString\n" + docstr);

		return docstr;
	}

	public static org.w3c.dom.Document readStringToDOM(String docstr)
			throws Exception {
		// start xml document processing part
		javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory
				.newInstance();

		//XML Signature needs to be namespace aware
		dbf.setNamespaceAware(true);
		javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
		// reading document
		org.w3c.dom.Document doc = db
				.parse(new StringBufferInputStream(docstr));
		//System.out.println("\nstring doc is now a DOM doc \n" );
		//printDOMdoc(doc);
		return doc;
	}

	public static String readDOMToString(org.w3c.dom.Document doc)
			throws Exception {
		// start xml document processing part

		//converting signed DOM doc to output String doc
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		XMLUtils.outputDOMc14nWithComments(doc, bos);
		String docstr = bos.toString();
		bos.close();
		//System.out.println("\nDOM doc is now a String doc \n" + docstr);
		return docstr;
	}

	public static void printDOMdoc(org.w3c.dom.Document doc) throws Exception {
		// print DOM doc
		ByteArrayOutputStream f = new ByteArrayOutputStream();
		XMLUtils.outputDOMc14nWithComments(doc, f);
		//System.out.println("\n" + f.toString());
		System.out.print("\n" + f);
		f.close();
	}

	public static void printStringdoc(String doc) throws Exception {
		// print DOM doc
		ByteArrayOutputStream f = new ByteArrayOutputStream();

		//XMLUtils.outputDOMc14nWithComments(doc, f);
		f.close();
		//System.out.println("\n" + f.toString());
		System.out.println("\n" + doc);
	}

	public static void saveDOMdoc(org.w3c.dom.Document doc, String filename)
			throws Exception {
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
		Constants.setSignatureSpecNSprefix("ds"); //# think about adding "ds:"
												  // prefix

		//Receive parameters for the keystore
		String keyalias = "cnl01";
		String infile = "aaareq01nons.xml";
		List checkconfsec = new ArrayList();
		List keyset = KeyStoreConfig.getConfigKeys(keyalias);

		// define parts of the document to be signed
		String uri2sign0 = "";
		String uri2sign1 = "#subject";
		String uri2sign2 = "#xpointer(id('subject'))";
		List uri2sign = new ArrayList();
		uri2sign.add(uri2sign0);
		uri2sign.add(uri2sign1);
		//uri2sign.add(uri2sign2);

		// components test block
		/*
		 * // readFileToDOM (String filename)
		 * javax.xml.parsers.DocumentBuilderFactory dbf =
		 * javax.xml.parsers.DocumentBuilderFactory.newInstance();
		 * 
		 * //XML Signature needs to be namespace aware
		 * dbf.setNamespaceAware(true); javax.xml.parsers.DocumentBuilder db =
		 * dbf.newDocumentBuilder(); // reading document org.w3c.dom.Document
		 * doc1 = db.parse(infile);
		 * 
		 * //testing input methods //System.out.println("Initial test block\n");
		 * //System.out.println("\nread file and print DOM doc\n");
		 * //org.w3c.dom.Document doc1 =
		 * testxmlsec.Example02SignDocument.readFileToDOM (infile);
		 * //org.w3c.dom.Document doc1 = readFileToDOM (infile);
		 * //printDOMdoc(doc1); //System.out.println("\nread file and print
		 * String doc\n"); //String docstr =
		 * testxmlsec.Example02SignDocument.readFileToString (infile); //String
		 * docstr = readFileToString (infile); //System.out.print(docstr);
		 * //System.out.println("\nread String doc and print DOM doc\n");
		 * //org.w3c.dom.Document doc2 =
		 * testxmlsec.Example02SignDocument.readStringToDOM(docstr);
		 * //org.w3c.dom.Document doc2 = readStringToDOM(docstr);
		 * //printDOMdoc(doc2);
		 */

		// call methods to read and sign external document
		try {
			System.out.println("\nRunning test for Enveloped XML Signature ");
			System.out.println("Select source option ( " + "0 - sign file, "
					+ "1 - sign DOM, " + "2 - sign string doc )");

			int s = HelpersReadWrite.readStdinInt();
			//printKeyInfo (keyalias);
			switch (s) {
			case 0: {
				CreateSignature.readAndSignFile(keyset, infile, uri2sign);
				return;
			}
			case 1: {
				printDOMdoc(CreateSignature.signDoc(keyset,
						readFileToDOM(infile), uri2sign));
				return;
			}
			case 2: {
				System.out.print(CreateSignature.signDoc(keyset,
						readFileToString(infile), uri2sign));
				return;
			}
			case 3: {
				System.out.print("signed version 4");
				return;
			}
			} //System.out.print(new StringBuffer (
			System.out.println("OK");
			System.exit(0);
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
	}
}
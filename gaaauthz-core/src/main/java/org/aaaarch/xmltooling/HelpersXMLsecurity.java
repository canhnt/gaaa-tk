/*
 * Created on May 3, 2004
 *
 * AIRG at UvA, Collaboratory.nl Project
 */
package org.aaaarch.xmltooling;

import java.io.*;
//import java.util.ArrayList;
import java.util.ArrayList;
import java.util.List;

import org.aaaarch.config.ConfigSecurity;
import org.aaaarch.config.KeyStoreConfig;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;

/**
 * @author Yuri Demchenko
 * 
 * AIRG at UvA, Collaboratory.nl Project
 */
public class HelpersXMLsecurity {
	final static String signatureSchemaFile = ConfigSecurity.LOCAL_DIR_SCHEMAS + "xmldsig-core-schema.xsd";

	//////////// Read/write helpers for XML Security ////////////////////
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

	public static org.w3c.dom.Document readFileToDOMvalidation(String filename,
			boolean schemaValidate) throws Exception {
		// start xml document processing part

		if (schemaValidate) {
			System.out.println("Schema validation is TRUE");
		}

		javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory
				.newInstance();

		if (schemaValidate) {
			dbf.setAttribute(
					"http://apache.org/xml/features/validation/schema",
					Boolean.TRUE);
			dbf.setAttribute(
					"http://apache.org/xml/features/dom/defer-node-expansion",
					Boolean.TRUE);
			dbf.setValidating(true);
			dbf.setAttribute("http://xml.org/sax/features/validation",
					Boolean.TRUE);
		}

		dbf.setNamespaceAware(true);
		dbf
				.setAttribute("http://xml.org/sax/features/namespaces",
						Boolean.TRUE);

		if (schemaValidate) {
			dbf
					.setAttribute(
							"http://apache.org/xml/properties/schema/external-schemaLocation",
							Constants.SignatureSpecNS + " "
									+ signatureSchemaFile);
		}

		File f = new File(filename);

		javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();

		db
				.setErrorHandler(new org.apache.xml.security.utils.IgnoreAllErrorHandler());

		if (schemaValidate) {
			db.setEntityResolver(new org.xml.sax.EntityResolver() {

				public org.xml.sax.InputSource resolveEntity(String publicId,
						String systemId) throws org.xml.sax.SAXException {

					if (systemId.endsWith("xmldsig-core-schema.xsd")) {
						try {
							return new org.xml.sax.InputSource(
									new FileInputStream(signatureSchemaFile));
						} catch (FileNotFoundException ex) {
							throw new org.xml.sax.SAXException(ex);
						}
					} else {
						return null;
					}
				}
			});
		}

		org.w3c.dom.Document doc = db.parse(new java.io.FileInputStream(f));

		return doc;
	}

	public static String readFileToString(String filename) throws Exception {
		// start xml document processing part
		javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory
				.newInstance();

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

	public static String convertDOMToString(org.w3c.dom.Document doc) throws Exception {
		// start xml document processing part

		ByteArrayOutputStream f = new ByteArrayOutputStream();
		XMLUtils.outputDOMc14nWithComments(doc, f);
		String docstr = f.toString();
		f.close();
		return docstr;
	}

	public static String convertDOMToString(org.w3c.dom.Node node) throws Exception {
		// start xml document processing part

		ByteArrayOutputStream f = new ByteArrayOutputStream();
		XMLUtils.outputDOMc14nWithComments(node, f);
		String docstr = f.toString();
		f.close();
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
		org.w3c.dom.Document doc = 
			db.parse(new ByteArrayInputStream(docstr.getBytes()));
		//System.out.println("\nstring doc is now a DOM doc \n" );
		//printDOMdoc(doc);
		return doc;
	}
	
	public static org.w3c.dom.Document readStringToDOM(String docstr, boolean nsaware)
			throws Exception {
		// start xml document processing part
		javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory
					.newInstance();

		if (nsaware) {
		//XML Signature needs to be namespace aware
		dbf.setNamespaceAware(true);}
		else {dbf.setNamespaceAware(false);} // some XML doc don't need NS awareness
		javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
		// reading document
		org.w3c.dom.Document doc = db.parse(new StringBufferInputStream(docstr));
		//System.out.println("\nstring doc is now a DOM doc \n" );
		//printDOMdoc(doc);
		return doc;
	}

	public static boolean isStringXML(String anystring)	throws Exception {
		// start xml document processing part
		boolean nsaware = true;
		boolean isxml = true;
		javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory
					.newInstance();
		
		if (nsaware) {
		//XML Signature needs to be namespace aware
		dbf.setNamespaceAware(true);}
		else {dbf.setNamespaceAware(false);} // some XML doc don't need NS awareness
		javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
		// reading document
		try {
		org.w3c.dom.Document doc = db.parse(new StringBufferInputStream(anystring));
		} catch (Exception ex) {
			isxml = false;
			System.out.println("\nHelpersXMLSecurity: String is not XML doc: \n" + anystring);
			//ex.printStackTrace();
		}
		
		return isxml;
	}
	
	
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

	public static void printDOMdoc(org.w3c.dom.Document doc) throws Exception {
		// print DOM doc
		ByteArrayOutputStream f = new ByteArrayOutputStream();
		XMLUtils.outputDOMc14nWithComments(doc, f);
		f.close();
		System.out.print("\n" + f);
	}

	public static void printDOMdoc(org.w3c.dom.Node element) throws Exception {
		// TODO: error in context doc 
		// print DOM doc
		ByteArrayOutputStream f = new ByteArrayOutputStream();
		XMLUtils.outputDOMc14nWithComments(element, f);
		f.close();
		//System.out.println("\n" + f.toString());
		System.out.print("\n" + f);
	}

	public static void saveDOMdoc(org.w3c.dom.Document doc, String filename)
			throws Exception {
		// save file from DOM doc
		FileOutputStream f = new FileOutputStream(filename);
		XMLUtils.outputDOMc14nWithComments(doc, f);
		f.close();
		//System.out.println("Wrote echo DOM doc to " + filename);
	}
	public static void writeToFile (Document doc, String filename) throws IOException {

		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		XMLUtils.outputDOMc14nWithComments(doc, bos);
		//String docstr = bos.toString();
		byte[] docbytes = bos.toString().getBytes();
		bos.close();
		// System.out.println("Document saved in file " + filename);
		
		File File = new File(filename);
	    FileOutputStream f = new FileOutputStream(File);
	    f.write(docbytes);
	    f.close();
	    
	}

	static {
		org.apache.xml.security.Init.init();
	}

}
/*
 * Copyright  2004-2005 AIRG.
 *
 */
package org.aaaarch.gaaapi.test.xmlsec;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.StringBufferInputStream;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.aaaarch.config.KeyStoreConfig;
import org.aaaarch.utils.HelpersReadWrite;
import org.aaaarch.utils.HelpersXMLsecurity;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.samples.utils.resolver.OfflineResolver;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xpath.XPathAPI;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * 
 * @author demch 
 *  
 */
public class Example10VerifySignature {
	final static String signatureSchemaFile = "data/schemas/xmldsig-core-schema.xsd";

	// read and validate File doc
	public static boolean validateDOMdoc(org.w3c.dom.Document doc, boolean schemaValidate) throws Exception {
		boolean validSig = false;
	    XMLSignature signature = null;
		//final String signatureSchemaFile = "data/schemas/xmldsig-core-schema.xsd";
		//final String signatureSchemaFile = "http://www.w3.org/TR/xmldsig-core/xmldsig-core-schema.xsd";

		if (schemaValidate) {
			System.out.println("Schema validation is TRUE");
		}
		javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();

		if (schemaValidate) {
			dbf.setAttribute("http://apache.org/xml/features/validation/schema", Boolean.TRUE);
			dbf.setAttribute("http://apache.org/xml/features/dom/defer-node-expansion",	Boolean.TRUE);
			dbf.setValidating(true);
			dbf.setAttribute("http://xml.org/sax/features/validation", Boolean.TRUE);
		}

		dbf.setNamespaceAware(true);
		dbf.setAttribute("http://xml.org/sax/features/namespaces", Boolean.TRUE);

		if (schemaValidate) {
			dbf.setAttribute("http://apache.org/xml/properties/schema/external-schemaLocation", 
					Constants.SignatureSpecNS + " " + signatureSchemaFile);
		}

		try {
			Element nscontext = XMLUtils.createDSctx(doc, "ds",
					Constants.SignatureSpecNS);
			Element sigElement = (Element) XPathAPI.selectSingleNode
							(doc, "//ds:Signature", nscontext);
			///
			System.out.println("Signature element extracted.\n");
			printDOMdoc(sigElement);
			System.out.println("\nProcessing...\n");
			///
			signature = new XMLSignature((Element)sigElement, null);
			signature.addResourceResolver(new OfflineResolver());

			KeyInfo ki = signature.getKeyInfo();
			if (ki != null) {
				if (ki.containsX509Data()) {
					System.out.println("Found a X509Data element in the KeyInfo. Verifying...");
				}

				X509Certificate cert = signature.getKeyInfo().getX509Certificate();

				if (cert != null) {
					System.out.println("\nNow is validating...\n");
					validSig = signature.checkSignatureValue(cert);
				} else {

					PublicKey pk = signature.getKeyInfo().getPublicKey();
					if (pk != null) {
						System.out
								.println("Found a public key in the KeyInfo. Verifying...");
						validSig = signature.checkSignatureValue(pk);
					} else {
						System.out.println("Did not find a X509Data either public key, " +
								"so can't verify the signature");
					}
				}
			} else {
				System.out.println("Did not find a KeyInfo");
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return validSig;
	}

	public static boolean validateStringDoc(String docstr, boolean schemaValidate) 
					throws Exception {
		boolean validSig = false;

		if (schemaValidate) {
			System.out.println("Schema validation is TRUE");
		}

		javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory
				.newInstance();

		if (schemaValidate) {
			dbf.setAttribute(
					"http://apache.org/xml/features/validation/schema", Boolean.TRUE);
			dbf.setAttribute(
					"http://apache.org/xml/features/dom/defer-node-expansion", Boolean.TRUE);
			dbf.setValidating(true);
			dbf.setAttribute("http://xml.org/sax/features/validation", Boolean.TRUE);
		}

		dbf.setNamespaceAware(true);
		dbf.setAttribute("http://xml.org/sax/features/namespaces", Boolean.TRUE);

		if (schemaValidate) {
			dbf.setAttribute("http://apache.org/xml/properties/schema/external-schemaLocation",
							Constants.SignatureSpecNS + " " + signatureSchemaFile);
		}

			javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();

			db.setErrorHandler(new org.apache.xml.security.utils.IgnoreAllErrorHandler());

			if (schemaValidate) {
				db.setEntityResolver(new org.xml.sax.EntityResolver() {

					public org.xml.sax.InputSource resolveEntity(
							String publicId, String systemId)
							throws org.xml.sax.SAXException {

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
		org.w3c.dom.Document doc = db.parse(new StringBufferInputStream(docstr));
		validSig = validateDOMdoc(doc, schemaValidate);
		return validSig;
	}
	
	public static boolean validateFileDoc(String signedFile, boolean schemaValidate) 
					throws Exception {
		boolean validSig = false;

		if (schemaValidate) {
			System.out.println("Schema validation is TRUE");
		}

		javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory
				.newInstance();

		if (schemaValidate) {
			dbf.setAttribute(
					"http://apache.org/xml/features/validation/schema", Boolean.TRUE);
			dbf.setAttribute(
					"http://apache.org/xml/features/dom/defer-node-expansion", Boolean.TRUE);
			dbf.setValidating(true);
			dbf.setAttribute("http://xml.org/sax/features/validation", Boolean.TRUE);
		}

		dbf.setNamespaceAware(true);
		dbf.setAttribute("http://xml.org/sax/features/namespaces", Boolean.TRUE);

		if (schemaValidate) {
			dbf.setAttribute("http://apache.org/xml/properties/schema/external-schemaLocation",
							Constants.SignatureSpecNS + " " + signatureSchemaFile);
		}

			javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();

			db.setErrorHandler(new org.apache.xml.security.utils.IgnoreAllErrorHandler());

			if (schemaValidate) {
				db.setEntityResolver(new org.xml.sax.EntityResolver() {

					public org.xml.sax.InputSource resolveEntity(
							String publicId, String systemId)
							throws org.xml.sax.SAXException {

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
		org.w3c.dom.Document doc = db.parse(signedFile);
		validSig = validateDOMdoc(doc, schemaValidate);
		return validSig;
	}

	public static boolean validateFileDefault(String signedFile, boolean schemaValidate) 
						throws Exception {
		boolean validSig = false;
		//final String signatureSchemaFile =
		// "data/schemas/xmldsig-core-schema.xsd";
		//final String signatureSchemaFile =
		// "http://www.w3.org/TR/xmldsig-core/xmldsig-core-schema.xsd";

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
		dbf.setAttribute("http://xml.org/sax/features/namespaces",
						Boolean.TRUE);

		if (schemaValidate) {
			dbf.setAttribute("http://apache.org/xml/properties/schema/external-schemaLocation",
							Constants.SignatureSpecNS + " " + signatureSchemaFile);
		}

		try {

			File f = new File(signedFile);

			javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();

			db.setErrorHandler(new org.apache.xml.security.utils.IgnoreAllErrorHandler());

			if (schemaValidate) {
				db.setEntityResolver(new org.xml.sax.EntityResolver() {

					public org.xml.sax.InputSource resolveEntity(
							String publicId, String systemId)
							throws org.xml.sax.SAXException {

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
			Element nscontext = XMLUtils.createDSctx(doc, "ds",
					Constants.SignatureSpecNS);
			Element sigElement = (Element) XPathAPI.selectSingleNode(doc,
					"//ds:Signature", nscontext);
			XMLSignature signature = new XMLSignature(sigElement, f.toURL()
					.toString());
			//XMLSignature signature = new XMLSignature(sigElement);
			printDOMdoc(sigElement);

			signature.addResourceResolver(new OfflineResolver());

			// XMLUtils.outputDOMc14nWithComments(signature.getElement(),
			// System.out);
			KeyInfo ki = signature.getKeyInfo();

			if (ki != null) {
				if (ki.containsX509Data()) {
					System.out.println("Found a X509Data element in the KeyInfo. Verifying...");
				}

				X509Certificate cert = signature.getKeyInfo().getX509Certificate();

				if (cert != null) {
					validSig = signature.checkSignatureValue(cert);
				} else {

					PublicKey pk = signature.getKeyInfo().getPublicKey();
					if (pk != null) {
						System.out
								.println("Found a public key in the KeyInfo. Verifying...");
						validSig = signature.checkSignatureValue(pk);
					} else {
						System.out
								.println("Did not find a X509Data either public key, so can't verify the signature");
					}
				}
			} else {
				System.out.println("Did not find a KeyInfo");
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return validSig;
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


	public static org.w3c.dom.Document readFileToDOMvalidation(String filename, boolean schemaValidate)
			throws Exception {
		// start xml document processing part

		if (schemaValidate) {
			System.out.println("Schema validation is TRUE");
		}

		javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory
				.newInstance();

		if (schemaValidate) {
			dbf.setAttribute(
					"http://apache.org/xml/features/validation/schema", Boolean.TRUE);
			dbf.setAttribute(
					"http://apache.org/xml/features/dom/defer-node-expansion", Boolean.TRUE);
			dbf.setValidating(true);
			dbf.setAttribute("http://xml.org/sax/features/validation", Boolean.TRUE);
		}

		dbf.setNamespaceAware(true);
		dbf.setAttribute("http://xml.org/sax/features/namespaces", Boolean.TRUE);

		if (schemaValidate) {
			dbf.setAttribute("http://apache.org/xml/properties/schema/external-schemaLocation",
							Constants.SignatureSpecNS + " " + signatureSchemaFile);
		}

			File f = new File(filename);

			javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();

			db.setErrorHandler(new org.apache.xml.security.utils.IgnoreAllErrorHandler());

			if (schemaValidate) {
				db.setEntityResolver(new org.xml.sax.EntityResolver() {

					public org.xml.sax.InputSource resolveEntity(
							String publicId, String systemId)
							throws org.xml.sax.SAXException {

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
		//System.out.println("\n" + f.toString());
		System.out.print("\n" + f);
	}

	public static void printDOMdoc(org.w3c.dom.Node element) throws Exception {
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

	static {
		org.apache.xml.security.Init.init();
	}

	public static void main(String unused[]) throws Exception {

		boolean schemaValidate = false;
		boolean validSig;

		final String signatureSchemaFile = "data/schemas/xmldsig-core-schema.xsd";
		// http://www.w3.org/TR/xmldsig-core/xmldsig-core-schema.xsd
		String infile = "signed-doc.xml";
		//String signedFileName = "signed-aaareq01nons.xml";
		//String signedFileName = "signed01-aaareq01nons.xml";
		//String signedFileName = "signed02subject-aaareq01nons.xml";
		//String signedFileName = "signed03rootsubject-aaareq01nons.xml";

		//File f = new File(infile);

	    // components test block
	    /*
	    System.out.println("Initial test block\n");
		System.out.println("\nread file and print DOM doc\n");
	    org.w3c.dom.Document doc1 = readFileToDOM (infile);
	    //printDOMdoc(doc1);
	    org.w3c.dom.Node node = doc1.getDocumentElement().getLastChild();
	    printDOMdoc(node);
		*/
		
		///////////// end of component test block
		
		try {
			System.out
					.println("\nRunning Example for Verifying XML Signature\n");
			System.out.println("Select Signature option ( "
					+ "0 - default test, \n"
					+ "1 - verify default file signed-doc.xml, "
					+ "2 - input DOM doc to verify, "
					+ "3 - select file from list)");

			int s = HelpersReadWrite.readStdinInt();
			//printKeyInfo (keyalias);
			switch (s) {
			case 0: {
				validSig = validateFileDefault(infile, schemaValidate);
				System.out.println("The XML signature in file "
						+ infile + " is "
						+ (validSig ? "=VALID=" : "=INVALID="));
				return;
			}
			case 1: {
				validSig = validateFileDoc(infile, schemaValidate);
				System.out.println("The XML signature in file "
						+ infile + " is "
						+ (validSig ? "=VALID=" : "=INVALID="));
				return;
			}
			case 2: {validSig = validateDOMdoc(readFileToDOM(infile), schemaValidate);
				//validSig = false;
				System.out.println("The XML signature in file "
						+ infile + " is "
						+ (validSig ? "=VALID=" : "=INVALID="));
				return;
			}
			}
			System.exit(0);
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}

	}
}
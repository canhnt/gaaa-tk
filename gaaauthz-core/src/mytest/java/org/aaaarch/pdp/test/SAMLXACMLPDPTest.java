/**
 * @author CanhNT
 *  
 * Created on Feb 09, 2011
 * SNE at UvA
 */
package org.aaaarch.pdp.test;

import java.io.*;
import java.util.Properties;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.aaaarch.pdp.SAMLXACMLPDP;
import org.aaaarch.pdp.impl.SimpleSAMLXACMLPDPImpl;
import org.aaaarch.pdp.impl.SimpleXACMLPDPImpl;
import org.aaaarch.policy.impl.FilePolicyFinderModule;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xacml.ctx.DecisionType;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionQueryType;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionStatementType;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

public class SAMLXACMLPDPTest {

	private static final String REQUEST_FILE = "D:/workspace/gaaauthz-bundles/gaaauthz-core/src/mytest/java/org/aaaarch/pdp/test/dummy-saml-xacml-request.xml";
	
	private static final String POLICY_PATH = "D:/workspace/public/data/policies";		
	
	static {
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
	}
	
	public SAMLXACMLPDPTest() {
	}

	public static void main(String args[]) throws IOException {

		SAMLXACMLPDPTest test = new SAMLXACMLPDPTest();

		test.doTest();		
	}

	private void doTest() {
		System.out.println("Test for XACML-PDP: org.aaaarch.pdp.impl.SimpleSAMLXACMLPDPImpl");
		
		System.out.print("Creating the SAMLXACMLPDP instance:...");
		
		Properties config = SimpleXACMLPDPImpl.getDefaultConfiguration();
		// replace the default policies store
		config.setProperty(FilePolicyFinderModule.POLICY_FINDER_MODULE_POLICY_PATH, POLICY_PATH);
		
		SAMLXACMLPDP _pdp = new SimpleSAMLXACMLPDPImpl(config);
		System.out.println("Done.");
		
		System.out.print("Loading SAML-XACML request from " + REQUEST_FILE + "...");
		XACMLAuthzDecisionQueryType request = loadRequest(REQUEST_FILE);
		
		if (request == null) {
			System.out.println("Error loading request file. Testing will exit");
			return;
		}
		System.out.println("Done.");
		
		System.out.print("Evaluating at the PDP:...");
		XACMLAuthzDecisionStatementType response = _pdp.evaluate(request);
		System.out.println("Done.");
		
		System.out.println("The evaluation result:");
		printResponse(response);
		
		DecisionType decision = response.getResponse().getResult().getDecision();
		
	}

	private void printResponse(XACMLAuthzDecisionStatementType response) {
//		OpenSAMLHelper.printSAMLObject(response);
		MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();

    	// Get the Subject marshaller
    	Marshaller marshaller = marshallerFactory.getMarshaller(response);

    	// Marshall the Subject
    	Element element;
		try {
			element = marshaller.marshall(response);
	    	System.out.println(org.opensaml.xml.util.XMLHelper.prettyPrintXML(element));
	    
		} catch (MarshallingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	private XACMLAuthzDecisionQueryType loadRequest(String filename) {

		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document doc = db.parse(filename);
			doc.getDocumentElement().normalize();
								
			UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
			Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(doc.getDocumentElement());
			
			XACMLAuthzDecisionQueryType request = null;
			try {
				request = (XACMLAuthzDecisionQueryType) unmarshaller.unmarshall(doc.getDocumentElement());
			} catch (UnmarshallingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			return request;
			
		} catch (ParserConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SAXException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}	
}

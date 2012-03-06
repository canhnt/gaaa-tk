/**
 * @author CanhNT
 *  
 * Created on Feb 09, 2011
 * SNE at UvA
 */
package org.aaaarch.pdp.test;

import java.io.*;
import java.util.Properties;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import oasis.names.tc.xacml._2_0.context.schema.os.RequestType;

import org.aaaarch.pdp.XACMLPDP;
import org.aaaarch.pdp.impl.SimpleXACMLPDPImpl;
import org.aaaarch.policy.impl.FilePolicyFinderModule;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import com.sun.xacml.ctx.ResponseCtx;

public class XACMLPDPTest {

	private static final String XACML_REQUEST_FILE = "D:/workspace/gaaauthz-bundles/gaaauthz-core/src/mytest/java/org/aaaarch/pdp/test/dummy-xacml-request.xml";
	
	private static final String POLICY_PATH = "D:/workspace/public/data/policies";	
	
	public XACMLPDPTest() {
	}

	public static void main(String args[]) throws IOException {

		XACMLPDPTest test = new XACMLPDPTest();

		test.doTest();		
	}

	private void doTest() {
		System.out.println("Test for XACML-PDP: org.aaaarch.pdp.impl.SimpleXACMLPDPImpl");
		
		System.out.print("Creating the XACMLPDP instance:...");
		
		Properties config = SimpleXACMLPDPImpl.getDefaultConfiguration();
		// replace the default policies store
		config.setProperty(FilePolicyFinderModule.POLICY_FINDER_MODULE_POLICY_PATH, POLICY_PATH);
		

		XACMLPDP xacmlPDP = new SimpleXACMLPDPImpl(config);
		System.out.println("Done.");
		
		System.out.print("Loading XACML request from " + XACML_REQUEST_FILE + "...");
		RequestType request = loadXACMLRequest(XACML_REQUEST_FILE);
		if (request == null) {
			System.out.println("Error. Testing will exit");
			return;
		}
		System.out.println("Done.");
		
		System.out.print("Evaluating at the PDP:...");
		ResponseCtx responseCtx = xacmlPDP.evaluate(request);
		System.out.println("Done.");
		
		System.out.println("The evaluation result:");
		printResponse(responseCtx);
	}

	private void printResponse(ResponseCtx responseCtx) {
		ByteArrayOutputStream out = new ByteArrayOutputStream(); 
		responseCtx.encode(out);
		System.out.println(out.toString());
	}

	private RequestType loadXACMLRequest(String filename) {

		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document doc = db.parse(filename);
			doc.getDocumentElement().normalize();
					
			RequestType request = unmarshallJAXB(RequestType.class, doc.getDocumentElement());
			
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
	
	public static <T> T unmarshallJAXB(Class<T> cls, Element domRequest) {		
		try {
			JAXBContext jc = JAXBContext.newInstance(cls);
			Unmarshaller unmarshaller = jc.createUnmarshaller();

			JAXBElement<T> jaxbObject = unmarshaller.unmarshal(domRequest, cls);
			
			return jaxbObject.getValue();			
		} catch (JAXBException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}				
		return null;
	}
}

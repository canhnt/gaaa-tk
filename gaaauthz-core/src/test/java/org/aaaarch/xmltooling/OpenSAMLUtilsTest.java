package org.aaaarch.xmltooling;

import static org.junit.Assert.*;

import java.io.IOException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.aaaarch.util.OpenSAMLUtil;
import org.junit.Test;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionQueryType;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.UnmarshallingException;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

public class OpenSAMLUtilsTest {

	public static String FILE_NAME = "src/test/resources/XADQ.xml";
	
	@Test
	public void testConvertXADQ() throws UnmarshallingException {
		
		initOpenSAML();
		
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

		//XML Signature needs to be namespace aware
		dbf.setNamespaceAware(true);

		DocumentBuilder db;
		try {
			db = dbf.newDocumentBuilder();
			Document doc = db.parse(FILE_NAME);
			
			XACMLAuthzDecisionQueryType xadq = OpenSAMLUtil.unmarshalXADQ(doc.getDocumentElement());
			System.out.println(OpenSAMLUtil.toString(xadq));
			
			assertNotNull(xadq);
			return;
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
		fail("Not yet implemented");
	}

	private void initOpenSAML() {
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.err.println(e);
		}
		
	}

}

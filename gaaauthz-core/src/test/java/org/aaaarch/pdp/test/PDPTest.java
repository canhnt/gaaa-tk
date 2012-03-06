package org.aaaarch.pdp.test;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.Properties;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.aaaarch.pdp.SAMLXACMLPDP;
import org.aaaarch.pdp.impl.SimpleSAMLXACMLPDPImpl;
import org.aaaarch.pdp.impl.SimpleXACMLPDPImpl;
import org.aaaarch.policy.impl.FilePolicyFinderModule;
import org.junit.Test;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xacml.ctx.DecisionType;
import org.opensaml.xacml.ctx.ResponseType;
import org.opensaml.xacml.ctx.ResultType;
import org.opensaml.xacml.ctx.DecisionType.DECISION;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionQueryType;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionStatementType;
import org.opensaml.xml.ConfigurationException;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import org.aaaarch.xmltooling.OpenSAMLUtils;

public class PDPTest {
	private static final String POLICY_PATH = "src/test/resources/policies/";
	private static final String PDP_CONFIG_FILE = "src/test/resources/XACMLPDPConfig.xml";
	private static final String REQUEST_FILE = "src/test/resources/XADQ-request.xml";

	static {
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	@Test
	public void testPDP() {
		
		Properties config = SimpleSAMLXACMLPDPImpl.getDefaultConfiguration();
		config.setProperty(FilePolicyFinderModule.POLICY_FINDER_MODULE_POLICY_PATH, POLICY_PATH);
		config.setProperty(SimpleXACMLPDPImpl.PDP_CONFIG_FILE, PDP_CONFIG_FILE);

		
		SAMLXACMLPDP pdp = new SimpleSAMLXACMLPDPImpl(config);
		
		XACMLAuthzDecisionQueryType xadq = readRequest(REQUEST_FILE);
			
		XACMLAuthzDecisionStatementType xads = pdp.evaluate(xadq);
		
		assertNotNull(xads);
		boolean decision = getDecisionValue(xads); 
		assertTrue(decision);
	}

	/**
	 * Return the boolean value of authorization decision inside the XACMLAuthzDecisionStatement response
	 * 
	 * @param xacmlAuthzDecisionStatement
	 * @return
	 */
	public static boolean getDecisionValue(XACMLAuthzDecisionStatementType xacmlAuthzDecisionStatement) {
		
		if (xacmlAuthzDecisionStatement == null) {
			throw new NullPointerException("xads argument must not be null"); 
		}
				
		ResponseType response = xacmlAuthzDecisionStatement.getResponse();
			
		ResultType result = response.getResult();
		assertNotNull(result);
		
		DecisionType decision = result.getDecision();		
		assertNotNull(decision);
		
		DECISION decisionValue = decision.getDecision();
		
		if (decisionValue == DECISION.Permit) {
			return true;
		}
		else if  (decisionValue == DECISION.Deny) {
			return false; 
		}
		else if (decisionValue == DECISION.Indeterminate || decisionValue == DECISION.NotApplicable) {
			return false;
		}
		
		return false;
	}

	private XACMLAuthzDecisionQueryType readRequest(String requestFile) {
		Document docRequest = null;
		try {
			docRequest = readXML(requestFile);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		if (docRequest != null)
			return OpenSAMLUtils.convertXADQ(docRequest.getDocumentElement());
		return null;
	}
	
	/**
	 * Return the DOM object Document from the reading xml file.
	 *  
	 * @param filename XML file to be read
	 * @return the Document object
	 * @throws ParserConfigurationException
	 * @throws SAXException
	 * @throws IOException
	 */
	public static Document readXML(String filename) throws ParserConfigurationException, SAXException, IOException {
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

		//XML Signature needs to be namespace aware
		dbf.setNamespaceAware(true);

		DocumentBuilder db;
		db = dbf.newDocumentBuilder();
		Document doc = db.parse(filename);
		return doc;
	}
}

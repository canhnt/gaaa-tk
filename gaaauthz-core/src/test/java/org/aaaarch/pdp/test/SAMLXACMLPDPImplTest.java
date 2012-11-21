package org.aaaarch.pdp.test;

import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.util.Arrays;

import javax.xml.parsers.ParserConfigurationException;

import org.aaaarch.pdp.PDPException;
import org.aaaarch.pdp.SAMLXACMLPDP;
import org.aaaarch.pdp.XACMLPDPAdapter;
import org.aaaarch.pdp.impl.SAMLXACMLPDPImpl;
import org.aaaarch.sunxacml.SunXACMLPDPAdapterBuilder;
import org.aaaarch.util.OpenSAMLUtil;
import org.junit.Test;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionQueryType;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionStatementType;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.UnmarshallingException;
import org.xml.sax.SAXException;

import com.sun.xacml.ParsingException;
import com.sun.xacml.UnknownIdentifierException;


public class SAMLXACMLPDPImplTest {

	private static final String REQUEST_FILE = "src/test/resources/XADQ.xml";
	
//	private java.util.logging.Logger logger =  java.util.logging.Logger.getLogger(SAMLXACMLPDPImplTest.class.getName());
	
	private static final transient org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(SAMLXACMLPDPImplTest.class);


	public static final String[] STATIC_POLICIES = {
		"src/test/resources/policies/RPS-VIO-Role.xml",
		"src/test/resources/policies/RPS-VIP-Role.xml",
		"src/test/resources/policies/RPS-VIO-IT-Role.xml"
	};
	
	public static final String[] STATIC_REF_POLICIES = {		
		"src/test/resources/policies/PPS-VIP-Role.xml", 
		"src/test/resources/policies/PPS-VIO-Role.xml",
//		"src/test/resources/policies/PPS-VIO-IT-Role.xml",
		"src/test/resources/policies/permission-request-vi.xml",
		"src/test/resources/policies/permission-instantiate-vi.xml",
		"src/test/resources/policies/permission-decommission-vi.xml"
		
	};

	static {
		System.out.println("Initializing OpenSAML library");
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			e.printStackTrace();
		}
	}
	
	@Test
	public void testSubjectRoleAdapter() throws ParsingException, UnknownIdentifierException, ParserConfigurationException, SAXException, IOException, PDPException, UnmarshallingException {
				
		XACMLPDPAdapter adapter = SunXACMLPDPAdapterBuilder.createSubjectRolebasedAdapter("src/test/resources/policies", log);
		
		SAMLXACMLPDP pdp = new SAMLXACMLPDPImpl(adapter);
		
		XACMLAuthzDecisionQueryType authzQuery = OpenSAMLUtil.unmarshalXADQ(REQUEST_FILE);
		
		XACMLAuthzDecisionStatementType authzResponse = pdp.evaluate(authzQuery);
				
		assertNotNull(authzResponse);
		
		System.out.println(OpenSAMLUtil.toString(authzResponse));
	}
	
	@Test
	public void testRBACAdapter() throws ParserConfigurationException, SAXException, IOException, PDPException, UnmarshallingException {
		log.info("Testing with RBAC policies");
		XACMLPDPAdapter adapter = SunXACMLPDPAdapterBuilder.createAdapter(
				Arrays.asList(STATIC_REF_POLICIES),Arrays.asList(STATIC_POLICIES));
				
		SAMLXACMLPDP pdp = new SAMLXACMLPDPImpl(adapter);
		
		XACMLAuthzDecisionQueryType authzQuery = OpenSAMLUtil.unmarshalXADQ(REQUEST_FILE);
		
		XACMLAuthzDecisionStatementType authzResponse = pdp.evaluate(authzQuery);
				
		assertNotNull(authzResponse);
		
		System.out.println(OpenSAMLUtil.toString(authzResponse));
	
	}
}

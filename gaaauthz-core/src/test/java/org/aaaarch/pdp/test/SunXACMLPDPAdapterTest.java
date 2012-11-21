package org.aaaarch.pdp.test;

import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.util.Arrays;
import javax.xml.parsers.ParserConfigurationException;

import oasis.names.tc.xacml._2_0.context.schema.os.RequestType;
import oasis.names.tc.xacml._2_0.context.schema.os.ResponseType;

import org.aaaarch.pdp.XACMLPDPAdapter;
import org.aaaarch.sunxacml.SunXACMLPDPAdapterBuilder;
import org.aaaarch.sunxacml.util.SunXACMLUtil;
import org.aaaarch.xmltooling.XMLHelper;
import org.junit.Test;
import org.xml.sax.SAXException;

import com.sun.xacml.ParsingException;
import com.sun.xacml.UnknownIdentifierException;


public class SunXACMLPDPAdapterTest {

	private static final String XACML_REQUEST_FILE = "src/test/resources/xacml-request.xml";
	
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

	@Test
	public void testSubjectRoleAdapter() throws ParsingException, UnknownIdentifierException, ParserConfigurationException, SAXException, IOException {
				
		XACMLPDPAdapter adapter = SunXACMLPDPAdapterBuilder.createSubjectRolebasedAdapter("src/test/resources/policies", log);
				
		RequestType request = SunXACMLUtil.unmarshalRequestType(XACML_REQUEST_FILE);
				
		System.out.println(XMLHelper.toString(SunXACMLUtil.marshall(request)));
		
		ResponseType resp = adapter.evaluate(request);
		
		assertNotNull(resp);
		
		System.out.println(XMLHelper.toString(SunXACMLUtil.marshal(resp)));
	}
	
	@Test
	public void testRBACAdapter() throws ParserConfigurationException, SAXException, IOException {
		log.info("Testing with RBAC policies");
		XACMLPDPAdapter adapter = SunXACMLPDPAdapterBuilder.createAdapter(
				Arrays.asList(STATIC_REF_POLICIES),Arrays.asList(STATIC_POLICIES));
				

		RequestType request = SunXACMLUtil.unmarshalRequestType(XACML_REQUEST_FILE);
		
		ResponseType resp = adapter.evaluate(request);
		
		assertNotNull(resp);			
		System.out.println(XMLHelper.toString(SunXACMLUtil.marshal(resp)));					
	}
}

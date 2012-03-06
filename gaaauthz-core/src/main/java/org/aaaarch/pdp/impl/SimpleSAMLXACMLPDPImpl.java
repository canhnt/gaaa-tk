/**
 * 
 */
package org.aaaarch.pdp.impl;

import java.io.IOException;
import java.util.Properties;

import javax.xml.bind.JAXBException;
import javax.xml.namespace.QName;
import javax.xml.parsers.ParserConfigurationException;

import org.aaaarch.pdp.SAMLXACMLPDP;
import org.aaaarch.utils.OpenSAMLHelper;
import org.aaaarch.utils.SunXACMLHelper;
import org.opensaml.Configuration;
import org.opensaml.xacml.ctx.RequestType;
import org.opensaml.xacml.ctx.ResponseType;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionQueryType;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionStatementType;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.schema.XSBooleanValue;
import org.xml.sax.SAXException;

/**
 * @author CanhNT
 *
 */
public class SimpleSAMLXACMLPDPImpl extends SimpleXACMLPDPImpl implements
		SAMLXACMLPDP {
	
	private static final transient org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(SimpleSAMLXACMLPDPImpl.class);
	
	public SimpleSAMLXACMLPDPImpl() {
		super();
	}
	
	public SimpleSAMLXACMLPDPImpl(Properties properties) {
		super(properties);
	}
	
	protected ResponseType evaluate(RequestType authzRequest) throws JAXBException, ParserConfigurationException, UnmarshallingException, SAXException, IOException {
		
		oasis.names.tc.xacml._2_0.context.schema.os.RequestType jaxbXACMLRequest = SunXACMLHelper.convertRequest(authzRequest);
		
		// evaluate authz request
		com.sun.xacml.ctx.ResponseCtx responseCtx = evaluate(jaxbXACMLRequest);					
											
		org.opensaml.xacml.ctx.ResponseType xacmlResponseOpenSAML = null;
		xacmlResponseOpenSAML = OpenSAMLHelper.createResponseType(responseCtx);
			
		debug(OpenSAMLHelper.printSAMLObject(xacmlResponseOpenSAML));
				
		return xacmlResponseOpenSAML;		
	}
	
	private void debug(String message) {
		log.info(message);
	}
	
	private void log(String message) {
		log.info(message);
	}

	/* (non-Javadoc)
	 * @see org.aaaarch.pdp.SAMLXACMLPDP#evaluate(org.opensaml.xacml.profile.saml.XACMLAuthzDecisionQueryType)
	 */
	public XACMLAuthzDecisionStatementType evaluate(
			XACMLAuthzDecisionQueryType authzQuery) {
		
		if (authzQuery == null)
			throw new IllegalArgumentException("The authzQuery must not be null");
		
		// Get the XACML request inside the XACMLAuthzDecisionQuery		
		RequestType xacmlRequest = authzQuery.getRequest();
		
		// And evaluate to the PDP
		ResponseType xacmlResponse = null;
		try {
			xacmlResponse = evaluate(xacmlRequest);
		} catch (JAXBException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		} catch (ParserConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		} catch (UnmarshallingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		} catch (SAXException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		
		XACMLAuthzDecisionStatementType authzStatement = OpenSAMLHelper.createXADS(authzQuery, xacmlResponse);
				
		return authzStatement;
	}
}

/**
 * 
 */
package org.aaaarch.pdp.impl;

import java.io.IOException;
import java.util.logging.Level;

import javax.xml.bind.JAXBException;
import javax.xml.parsers.ParserConfigurationException;

import org.aaaarch.pdp.PDPException;
import org.aaaarch.pdp.SAMLXACMLPDP;
import org.aaaarch.pdp.XACMLPDPAdapter;
import org.aaaarch.sunxacml.SunXACMLPDPAdapter;
import org.aaaarch.sunxacml.util.SunXACMLUtil;
import org.aaaarch.util.OpenSAMLUtil;
import org.opensaml.xacml.ctx.RequestType;
import org.opensaml.xacml.ctx.ResponseType;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionQueryType;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionStatementType;
import org.opensaml.xml.io.UnmarshallingException;
import org.xml.sax.SAXException;

/**
 * @author CanhNT
 * 
 */
public class SAMLXACMLPDPImpl implements SAMLXACMLPDP {

	// private static final transient org.slf4j.Logger log =
	// org.slf4j.LoggerFactory
	// .getLogger(SAMLXACMLPDPImpl.class);

	private static final transient java.util.logging.Logger log = java.util.logging.Logger
			.getLogger(SAMLXACMLPDPImpl.class.getName());

	private XACMLPDPAdapter pdpAdpater;

	public SAMLXACMLPDPImpl(XACMLPDPAdapter adapter) {
		this.pdpAdpater = adapter;
	}

	protected ResponseType evaluate(RequestType authzRequest)
			throws JAXBException, ParserConfigurationException,
			UnmarshallingException, SAXException, IOException {

		// evaluate authz request
		ResponseType xacmlResponseOpenSAML = SunXACMLUtil
				.convertResponse(pdpAdpater.evaluate(SunXACMLUtil
						.convertRequest(authzRequest)));

		//log.log(Level.INFO, OpenSAMLUtil.toString(xacmlResponseOpenSAML));

		return xacmlResponseOpenSAML;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.aaaarch.pdp.SAMLXACMLPDP#evaluate(org.opensaml.xacml.profile.saml
	 * .XACMLAuthzDecisionQueryType)
	 */
	public XACMLAuthzDecisionStatementType evaluate(
			XACMLAuthzDecisionQueryType query) throws PDPException {

		if (query == null)
			throw new IllegalArgumentException(
					"The authzQuery must not be null");

		// Get the XACML request inside the XACMLAuthzDecisionQuery
		RequestType xacmlRequest = query.getRequest();

		// And evaluate to the PDP
		ResponseType xacmlResponse = null;
		try {
			xacmlResponse = evaluate(xacmlRequest);
			XACMLAuthzDecisionStatementType authzStatement = OpenSAMLUtil
					.createXADS(query, xacmlResponse);

			return authzStatement;
		} catch (Exception e) {
			throw new PDPException("Some errors occured", e);
		}
	}
}

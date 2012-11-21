/**
 * 
 */
package org.aaaarch.pdp;

import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionQueryType;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionStatementType;

/**
 * @author CanhNT
 *
 */
public interface SAMLXACMLPDP {
	public XACMLAuthzDecisionStatementType evaluate(XACMLAuthzDecisionQueryType authzQuery) throws PDPException;
}

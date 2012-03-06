/*
 * Created on Feb 7, 2005
 *
 */
package org.aaaarch.config;

/**
 * @author demch
 * 
 * Defines the trust domain identifier for debugging/demo purposes
 * Identifies possible remote PEP and PDP location:
 * - PEP is protecting Resource, and therefore should be located in 
 *   the Resource trust domain
 * - PDP may be remote, in this case communication between PEP and PDP  
 *   must be protected cryptographically 
 *   
 *   Additional configuration parameter:
 *   - trust/session credentials format:
 *   	* aaa:ticket
 *   	* aaa:ticket:saml
 *   	* aaa:ticket:wst
 *   	* aaa:token
 */
public class ConfigTrustDomains {

	// AAA components' Trust domain identifiers
	public static final String TRUSTDOMAIN_AUTHZ_PEP = "x-urn:aaa:trust:pep";
	public static final String TRUSTDOMAIN_AUTHZ_PDP = "x-urn:aaa:trust:pdp";
	public static final String TRUSTDOMAIN_AUTHZ_PEP_PDP = "x-urn:aaa:trust:pep-pdp";
	// TODO: Revise TicketAuthority to domain aware name or even FQN
	public static final String TICKETAUTHORITY_PEP = "x-urn:aaa:trust:tickauth:pep";
	public static final String TICKETAUTHORITY_PDP = "x-urn:aaa:trust:tickauth:pdp";
	public static final String SESSION_TICKET_AAA = "aaa:ticket";
	public static final String SESSION_TICKET_SAML = "aaa:ticket:saml";
	public static final String SESSION_TICKET_WST = "aaa:ticket:wst";
	public static final String SESSION_TOKEN = "aaa:token";

 	/// Issuer Authority Id's
 	// Functional components
//	public static final String AAA_TICKET_ISSUER = ConfigDomainsPhosphorus.DOMAIN_PHOSPHORUS_AAA_DEFAULT + "/" + "TicketAuthority";
// 	public static final String AAA_TOKEN_ISSUER = ConfigDomainsPhosphorus.DOMAIN_PHOSPHORUS_AAA_DEFAULT + "/" + "TVS";
//	// TODO: Provisional values - may have domain/resource defined values
	public static final String REALM_PHOSPHORUS = "http://testbed.ist-phosphorus.eu";
	public static final String DOMAIN_PHOSPHORUS_DEFAULT = REALM_PHOSPHORUS + "/" + "phosphorus";
	public static final String DOMAIN_PHOSPHORUS_AAA_DEFAULT = DOMAIN_PHOSPHORUS_DEFAULT + "/" + "aaa";

 	public static final String AAA_ATTRIBUTE_ISSUER = DOMAIN_PHOSPHORUS_AAA_DEFAULT + "/" + "AttributeIssuer";


}

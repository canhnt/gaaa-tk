/**
 * GAAA-TK Library
 * Copyright (c) 2011
 * System and Network Engineering Group, University of Amsterdam.
 * All rights reserved
 */
package org.aaaarch.policy.impl;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.List;
import java.util.Properties;
import java.util.ResourceBundle;

import oasis.names.tc.xacml._2_0.context.schema.os.AttributeType;
import oasis.names.tc.xacml._2_0.context.schema.os.RequestType;
import oasis.names.tc.xacml._2_0.context.schema.os.SubjectType;

import org.aaaarch.policy.PolicyException;
import org.aaaarch.policy.PolicyResolver;

/**
 * @author <A HREF="mailto:T.C.Ngo@uva.nl">Canh Ngo</A>
 * @version 0.1
 * @date: Mar 15, 2011
 * 
 */

/**
 * Return the policy file path based on XACML request.
 * 
 * File path:
 * 	POLICY_DIR + "/" + subjectId + "-policy.xml"
 */
public class FilePolicyResolver implements PolicyResolver {

	private static final transient org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(FilePolicyResolver.class);
	
	private static final String POLICY_FILE_SUFFIX = "-policy.xml";
			
	protected String _policyDir;
			
	/**
	 * 
	 * @param props contains configuration to the FilePolicyResolver, including the policy folder location
	 */
	public FilePolicyResolver(String policyDir) {
		if (policyDir == null || policyDir.isEmpty())
			throw new IllegalArgumentException("Policy folder setting is null or empty");
		
		log.info("Policy Folder location: " + policyDir);
		_policyDir = policyDir;
	}
		
	/* (non-Javadoc)
	 * @see org.aaaarch.policy.PolicyResolver#lookup(oasis.names.tc.xacml._2_0.context.schema.os.RequestType)
	 */
	public String lookup(RequestType xamlcRequest) throws PolicyException {
		
		log.info("Looking up policies at " + _policyDir);
		
		List<SubjectType> subjects = xamlcRequest.getSubject();
		
		if (subjects == null || subjects.size() == 0)
			throw new PolicyException("No Subject element found in the XACML request");
		
		SubjectType subject = subjects.get(0); // get the first subject only
		
		String subjectRole = null;
		
		for (AttributeType attr: subject.getAttribute()) {
			if (attr.getAttributeId().equalsIgnoreCase("http://authz-interop.org/AAA/xacml/subject/subject-role")) {
				subjectRole = (String)attr.getAttributeValue().get(0).getContent().get(0);
				break;
			}				
		}
		
		if (subjectRole == null || subjectRole.isEmpty())
			throw new PolicyException("No SubjectRole attribute found in the XACML request");
		
		return _policyDir + "/" + subjectRole + POLICY_FILE_SUFFIX;
		
	}

}

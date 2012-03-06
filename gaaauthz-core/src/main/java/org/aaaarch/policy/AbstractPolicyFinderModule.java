/**
 * GAAA-TK Library
 * Copyright (c) 2011
 * System and Network Engineering Group, University of Amsterdam.
 * All rights reserved
 */
package org.aaaarch.policy;

import java.util.Properties;

import oasis.names.tc.xacml._2_0.context.schema.os.RequestType;

import com.sun.xacml.finder.PolicyFinder;
import com.sun.xacml.finder.PolicyFinderModule;

/**
 * @author <A HREF="mailto:T.C.Ngo@uva.nl">Canh Ngo</A>
 * @version 0.1
 * @date: Mar 15, 2011
 * 
 */
public abstract class AbstractPolicyFinderModule extends PolicyFinderModule {
	
	private static final transient org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(AbstractPolicyFinderModule.class);
	
	protected PolicyResolver _policyResolver;
	
	protected PolicyFinder _finder;
	
	protected Properties _propsConfig;
	
	/**
	 * Configuration for the PolicyFinderModule instance
	 * 
	 * @param properties
	 */
	public AbstractPolicyFinderModule(Properties props) {
		_propsConfig = props;
		log.info("Loading AbstractPolicyFinderModule configuration :" + _propsConfig);
	}
	
	/* (non-Javadoc)
	 * @see com.sun.xacml.finder.PolicyFinderModule#init(com.sun.xacml.finder.PolicyFinder)
	 */
	@Override
	public void init(PolicyFinder finder) {
		_finder = finder;
	}
	
	/**
	 * Load policies based on XACML request parameters.
	 * 
	 * @param xacmlRequest
	 * @throws PolicyException 
	 */
	public abstract void loadPolicies(RequestType xacmlRequest) throws PolicyException;
}

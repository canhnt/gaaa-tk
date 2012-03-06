/**
 * GAAA-TK Library
 * Copyright (c) 2011
 * System and Network Engineering Group, University of Amsterdam.
 * All rights reserved
 */
package org.aaaarch.policy.impl;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Properties;
import java.util.ResourceBundle;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import oasis.names.tc.xacml._2_0.context.schema.os.RequestType;

import org.aaaarch.pdp.PDPConstants;
import org.aaaarch.pdp.impl.SimpleSAMLXACMLPDPImpl;
import org.aaaarch.policy.AbstractPolicyFinderModule;
import org.aaaarch.policy.PolicyException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import com.sun.xacml.AbstractPolicy;
import com.sun.xacml.EvaluationCtx;
import com.sun.xacml.MatchResult;
import com.sun.xacml.Policy;
import com.sun.xacml.PolicySet;
import com.sun.xacml.ctx.Status;
import com.sun.xacml.finder.PolicyFinderResult;
import com.sun.xacml.support.finder.PolicyCollection;
import com.sun.xacml.support.finder.TopLevelPolicyException;

/**
 * @author <A HREF="mailto:T.C.Ngo@uva.nl">Canh Ngo</A>
 * @version 0.1
 * @date: Mar 15, 2011
 * 
 */

/*
 * A file-based extension of PolicyFinderModule class: provide policy from xml file name to the PDP.
 *  
 */
public class FilePolicyFinderModule extends AbstractPolicyFinderModule {

	private static final transient org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(FilePolicyFinderModule.class);

//	public static final String POLICY_FINDER_MODULE_CONFIG_FILE = "/eu/geysers/licl/aai/authzsvc/FilePolicyFinderModuleGeysers.properties"; //"/org/aaaarch/policy/impl/FilePolicyFinderModule.properties";
	
	public static final String POLICY_FINDER_MODULE_POLICY_PATH =  PDPConstants.POLICY_FINDER_MODULE_PREFIX + "_POLICY_PATH";

    private static final String XML_ELEMENT_POLICY_SET = "PolicySet";
    
	private static final String XML_ELEMENT_POLICY = "Policy";

	/*
	 * The policies used by PDP to evaluate a Request
	 * (defined by request attributes or loaded from the default storage)     
	 */
//    private HashMap<String, AbstractPolicy> _policies = null;
	PolicyCollection policies = null;
      	
    private DocumentBuilderFactory _dbf;
    
    private DocumentBuilder _docBuilder;

//    protected Properties _properties;	 
        
    public FilePolicyFinderModule(Properties props) throws PolicyException {
    	super(props);
    	try {    		   	
    		_policyResolver = new FilePolicyResolver(_propsConfig.getProperty(POLICY_FINDER_MODULE_POLICY_PATH));

//    		_policies = new HashMap<String, AbstractPolicy>();
    		policies = new PolicyCollection();
    		
    		 // create the DOM factory
    		_dbf = DocumentBuilderFactory.newInstance();
    		_dbf.setIgnoringComments(true);
    		_dbf.setNamespaceAware(true);
    		_dbf.setValidating(false);
    		
    		// create a DOM builder for policy loading
    		_docBuilder = _dbf.newDocumentBuilder();
    		
    	}catch(Exception e) {
    		e.printStackTrace();
			throw new PolicyException(e);
    	}              
	}
	
//    private Properties loadConfiguration(String propsFile) throws PolicyException {
//		try {
////			URL localURL = ClassLoader.getSystemResource(propsFile);
////			InputStream is = localURL.openStream();
////			InputStream is = new FileInputStream(propsFile);
////			"/org/aaaarch/policy/impl/FilePolicyFinderModule.properties"
////			"/eu/geysers/licl/aai/authzsvc/FilePolicyFinderModuleGeysers.properties"
//			InputStream is = this.getClass().getResourceAsStream(POLICY_FINDER_MODULE_CONFIG_FILE);
//			if (is == null) {				
//				return null;
//			}
//			Properties props  = new Properties();
//			props.load(is);
//			
//			return props;
//		}catch(IOException e) {
//			e.printStackTrace();		
//			throw new PolicyException("Could not load properties file at " + propsFile, e);				
//		}
//	}

	/**
     * Finds the applicable policy (if there is one) for the given context.
     *
     * @param context the evaluation context
     * @return an applicable policy, if one exists, or an error
     */	 
	public PolicyFinderResult findPolicy(EvaluationCtx context) {
        
		try {
			AbstractPolicy policy = policies.getPolicy(context);
	        if (policy == null)
	        	return new PolicyFinderResult();
	        else
	        	return new PolicyFinderResult(policy);	        
		} catch (TopLevelPolicyException e) {
			// TODO Auto-generated catch block
			return new PolicyFinderResult(e.getStatus());
		}
	}
	 
	public boolean isIdReferenceSupported() {
		return false;
	}
	
	/**
	 * Only support find policy from request
	 */
	public boolean isRequestSupported() {
		return true;
	}


	@Override
	public void loadPolicies(RequestType xacmlRequest) throws PolicyException {
		
		String policyFile = _policyResolver.lookup(xacmlRequest);
		log.info("Loading policie file: " + policyFile );
		//loading file
		AbstractPolicy policy = loadPolicy(policyFile);
		
		policies.addPolicy(policy);		
	}


	private AbstractPolicy loadPolicy(String filename) throws PolicyException {
		try {
	        Document doc = _docBuilder.parse(new FileInputStream(filename));
	        
	        // handle the policy, if it's a known type
	        Element root = doc.getDocumentElement();
	        String name = root.getLocalName();
	        
	        if (name.equalsIgnoreCase(XML_ELEMENT_POLICY)) {
	            return Policy.getInstance(root);
	        } else if (name.equalsIgnoreCase(XML_ELEMENT_POLICY_SET)) {
	            return PolicySet.getInstance(root, _finder);
	        }
	        
	        throw new PolicyException("Invalid policy file content");	        
		} catch (FileNotFoundException e) {			
//			e.printStackTrace();
			throw new PolicyException("Policy file "  + filename + " not found", e);
		} catch (SAXException e) {			
//			e.printStackTrace();
			throw new PolicyException("Error SAX parsing policy file " + filename, e);
		} catch (IOException e) {			
//			e.printStackTrace();
			throw new PolicyException("Error in IO operations to policy file " + filename, e);
		} catch (com.sun.xacml.ParsingException e) {			
//			e.printStackTrace();
			throw new PolicyException("Invalid parsing DOM policy file " + filename, e);
		}
	}
	 
}

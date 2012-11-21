/**
 * System and Network Engineering Group
 * University of Amsterdam
 *
 */
package org.aaaarch.sunxacml.util;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.sun.xacml.AbstractPolicy;
import com.sun.xacml.ParsingException;
import com.sun.xacml.finder.PolicyFinder;
import com.sun.xacml.support.finder.PolicyReader;

/**
 * @author Canh Ngo (t.c.ngo@uva.nl)
 *
 * @version 
 * @date: Mar 16, 2012
 */
public class PolicyUtil {
	
	/**
	 * Loading policy from URI or file path
	 * 
	 * @param finder
	 * @param log
	 * @param str
	 * @return
	 */
	public static AbstractPolicy loadPolicy(PolicyFinder finder, org.slf4j.Logger log, String str) {
        PolicyReader reader = new PolicyReader(finder, null, null);
        
        AbstractPolicy policy = null;
        try {
        	try {
            	// try to load as URL
            	URL url = new URL(str);
                policy = reader.readPolicy(url);
            }catch (MalformedURLException e) {
            	// then try with file load
            	policy = reader.readPolicy(new File(str));
            }
            	
        }catch (ParsingException pe) {
    		log.warn("Error reading policy: " + str, pe);
        }
        return policy;
	}
}

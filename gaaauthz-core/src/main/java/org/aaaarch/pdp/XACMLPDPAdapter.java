/**
 * System and Network Engineering Group
 * University of Amsterdam
 *
 */
package org.aaaarch.pdp;

import oasis.names.tc.xacml._2_0.context.schema.os.RequestType;
import oasis.names.tc.xacml._2_0.context.schema.os.ResponseType;

/**
 * @author Canh Ngo (t.c.ngo@uva.nl)
 *
 * @version 
 * @date: Mar 15, 2012
 */
public interface XACMLPDPAdapter {
	
	ResponseType evaluate(RequestType request);	
}

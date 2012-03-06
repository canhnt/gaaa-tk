/**
 * 
 */
package org.aaaarch.pdp;

import oasis.names.tc.xacml._2_0.context.schema.os.RequestType;

import com.sun.xacml.ctx.RequestCtx;
import com.sun.xacml.ctx.ResponseCtx;

/**
 * @author CanhNT
 *
 */
public interface XACMLPDP {	
	/**
	 * 
	 * @param request
	 * @deprecated As of release2.0, replaced by {@link #evaluate(RequestType)}
	 * @return
	 */
//	public ResponseCtx evaluate(RequestCtx request);
	
	/**
	 * Evaluate an XACML authorization request
	 * 
	 * @param request
	 * @return
	 */
	public ResponseCtx evaluate(RequestType request);	
}

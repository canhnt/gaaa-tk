/**
 * GAAA-TK Library
 * Copyright (c) 2011
 * System and Network Engineering Group, University of Amsterdam.
 * All rights reserved
 */
package org.aaaarch.policy;

/**
 * @author <A HREF="mailto:T.C.Ngo@uva.nl">Canh Ngo</A>
 * @version 
 * @date: Mar 15, 2011
 * 
 */
public class PolicyException extends Exception {
	public PolicyException(String s) {
		super(s);
	}
	public PolicyException(Exception e) {
		super(e);
	}
	public PolicyException(String s, Exception e) {
		super(s, e);
	}
}

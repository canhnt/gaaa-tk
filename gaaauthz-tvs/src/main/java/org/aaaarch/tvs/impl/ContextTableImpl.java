/**
 * 
 */
package org.aaaarch.tvs.impl;

import java.util.HashMap;

import org.aaaarch.tvs.AuthorizationContext;
import org.aaaarch.tvs.ContextTable;

/**
 * @author <A HREF="mailto:T.C.Ngo@uva.nl">Canh Ngo</A>
 * @version $Revision 0.1 $Date: 2010/03/02
 */

/**
 * A simple implementation of ContextTable 
 */
public class ContextTableImpl implements ContextTable {
	
	private HashMap<String, AuthorizationContext> 	_contextMap;
	
	public ContextTableImpl() {
		_contextMap = new HashMap<String, AuthorizationContext>();
	}
	
	public void put(String key, AuthorizationContext value) {
		_contextMap.put(key, value);
	}

	public AuthorizationContext get(String key) {
		return _contextMap.get(key);
	}

	public AuthorizationContext remove(String key) {
		
		return _contextMap.remove(key);
	}

	/**
	 * @uml.property  name="multiDomainContextTables"
	 * @uml.associationEnd  inverse="contextTableImpl:org.aaaarch.tvs.impl.MultiDomainContextTables"
	 */
	private MultiDomainContextTables multiDomainContextTables;

	/**
	 * Getter of the property <tt>multiDomainContextTables</tt>
	 * @return  Returns the multiDomainContextTables.
	 * @uml.property  name="multiDomainContextTables"
	 */
	public MultiDomainContextTables getMultiDomainContextTables() {
		return multiDomainContextTables;
	}

	/**
	 * Setter of the property <tt>multiDomainContextTables</tt>
	 * @param multiDomainContextTables  The multiDomainContextTables to set.
	 * @uml.property  name="multiDomainContextTables"
	 */
	public void setMultiDomainContextTables(
			MultiDomainContextTables multiDomainContextTables) {
		this.multiDomainContextTables = multiDomainContextTables;
	}

}

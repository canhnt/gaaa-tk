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
 * Manage ContextTable in multi-domain environment. Each entry is the ContextTable of a specific domain
 * - Add new ContextTable
 * - Get existing ContextTable by domain identifier
 * - Remove a ContextTable
 */
public class MultiDomainContextTables {
	
	private HashMap<String, ContextTable>	_mapDomainCtxTables;
	
	public MultiDomainContextTables() {
		_mapDomainCtxTables = new HashMap<String, ContextTable>();
	}
	
	public void putContextTable(String domain, ContextTable value) {
		_mapDomainCtxTables.put(domain, value);
	}
	
	public void put(String domain, String sessionId, AuthorizationContext authzCtx) {
		ContextTable currentCtxTable = getContextTable(domain);
		currentCtxTable.put(sessionId, authzCtx);
		// put back to multi-domain context tables
//		_mapDomainCtxTables.put(domain, currentCtxTable);
	}
	
	public ContextTable getContextTable(String domain) {
		ContextTable currentCtxTable = _mapDomainCtxTables.get(domain);
		if (currentCtxTable == null) {
			currentCtxTable = new ContextTableImpl();
		}
		_mapDomainCtxTables.put(domain, currentCtxTable);
		
		return currentCtxTable;
	}
	
	public ContextTable removeContextTable(String domain) {
		return _mapDomainCtxTables.remove(domain);
	}
}

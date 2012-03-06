/**
 * 
 */
package org.aaaarch.tvs;

/**
 * @author <A HREF="mailto:T.C.Ngo@uva.nl">Canh Ngo</A>
 * @version $Revision 0.1 $Date: 2010/03/02
 */

/**
 * ContextTable instance is to manage authorization contexts. Operations of the context table is
 * - Add new context
 * - Get existing context by index
 * - Remove a context
 */
public interface ContextTable{
	public void put(String key, AuthorizationContext value);
	
	public AuthorizationContext get(String key);
	
	public AuthorizationContext remove(String key);	
}

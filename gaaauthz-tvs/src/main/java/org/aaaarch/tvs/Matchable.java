/**
 * 
 */
package org.aaaarch.tvs;

/**
 * @author <A HREF="mailto:T.C.Ngo@uva.nl">Canh Ngo</A>
 * @version $Revision 0.1 $Date: 2010/03/02
 */

/**
 * Interface for matching object in the authorization context
 * - match method: the predicate object is matching with the subject object  
 */
public interface Matchable <T> {
	public boolean match(T object);
}

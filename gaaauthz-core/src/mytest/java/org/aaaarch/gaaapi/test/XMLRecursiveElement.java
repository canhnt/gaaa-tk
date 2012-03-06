package org.aaaarch.gaaapi.test;
import java.io.PushbackInputStream;

import org.apache.axiom.om.OMElement;
import org.apache.axis2.AxisFault;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

//import br.com.adilson.soap.security.xmlblocking.XMLBlockAttackClient;
//import br.com.adilson.soap.security.xmlblocking.XMLBlockAttackServer;


public class XMLRecursiveElement //implements XMLBlockAttackClient 
	{

	private static final Log log = LogFactory.getLog(XMLRecursiveElement.class);

	public void processDocument(OMElement documentElement) throws AxisFault {

		log.info("--> XMLRecursiveElement");
		//TODO to be implemented
		 
		try {
			if (1 > 5000) {
				throw new AxisFault("Document is too big! Processing error! Too many elements [" + 1 + "]");
			}
		} catch (AxisFault e) {
			log.error(e);
			throw e;
		} catch (Exception e) {
			log.error(e);
			e.printStackTrace();
			throw new AxisFault(e.getMessage(), e);
		}
	}

}

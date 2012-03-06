package org.aaaarch.xmltooling;

import org.opensaml.Configuration;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionQueryType;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.w3c.dom.Element;

public class OpenSAMLUtils {
	
	public static XACMLAuthzDecisionQueryType convertXADQ(Element element) {

		Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(XACMLAuthzDecisionQueryType.DEFAULT_ELEMENT_NAME_XACML20);
		
		try {
			XACMLAuthzDecisionQueryType xadq = (XACMLAuthzDecisionQueryType) unmarshaller.unmarshall(element);
			
			return xadq;
		} catch (UnmarshallingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;
	}
	
	public static String toString(XMLObject xmlObject)  {
    	// Get the marshaller factory
    	MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();

    	// Get the Subject marshaller
    	Marshaller marshaller = marshallerFactory.getMarshaller(xmlObject);

    	// Marshall the Subject
    	Element element;
		try {
			element = marshaller.marshall(xmlObject);
	    	return org.opensaml.xml.util.XMLHelper.prettyPrintXML(element);
	    
		} catch (MarshallingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
}

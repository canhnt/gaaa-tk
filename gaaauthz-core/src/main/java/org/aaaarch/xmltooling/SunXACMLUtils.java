package org.aaaarch.xmltooling;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import oasis.names.tc.xacml._2_0.context.schema.os.RequestType;

import org.w3c.dom.Element;

public class SunXACMLUtils {

	
	/**
	 * Unmarshall from DOM Element to oasis.names.tc.xacml._2_0.context.schema.os.RequestType
	 * 
	 * @param domRequest
	 * @return
	 */
	public static RequestType convertRequestType(Element domRequest) {
		return unmarshall(RequestType.class, domRequest);
	}
	
	
	/**
	 * Unmarshall from DOM Element to a generic JAXBElement
	 * 
	 * @param <T>
	 * @param cls
	 * @param domRequest
	 * @return
	 */
	public static <T> T unmarshall(Class<T> cls,
			Element domRequest) {
		
		try {
			JAXBContext jc = JAXBContext.newInstance(cls);
			Unmarshaller unmarshaller = jc.createUnmarshaller();

			JAXBElement<T> jaxbObject = unmarshaller.unmarshal(domRequest, cls);
			
			return jaxbObject.getValue();			
		} catch (JAXBException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}				
		return null;
	}
}

/**
 * 
 */
package org.aaaarch.utils;

import java.io.ByteArrayInputStream;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.opensaml.xacml.ctx.ResponseType;
import org.opensaml.xml.io.MarshallingException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.sun.xacml.ParsingException;
import com.sun.xacml.ctx.ResponseCtx;
import oasis.names.tc.xacml._2_0.context.schema.os.ObjectFactory;
import oasis.names.tc.xacml._2_0.context.schema.os.RequestType;

/**
 * Convert from OpenSAML datatypes to SunXACML datatypes
 * 
 * @author CanhNT
 *
 */
public class SunXACMLHelper {
	
	/**
	 * Convert from org.opensaml.xacml.ctx.RequestType in OpenSAML to 
	 * oasis.names.tc.xacml._2_0.context.schema.os.RequestType in SunXACML
	 * 
	 * @param xacmlRequestOpenSAML
	 * @return
	 */
	public static RequestType convertRequest(org.opensaml.xacml.ctx.RequestType xacmlRequestOpenSAML) {
		
		Element domElement;
		
		try {
			domElement = OpenSAMLHelper.marshall(xacmlRequestOpenSAML);
		} catch (MarshallingException e) {
			e.printStackTrace();
			return null;
		}
		
		return unmarshallRequest(domElement);
	}

	/**
	 * Unmarshall from DOM Element to oasis.names.tc.xacml._2_0.context.schema.os.RequestType
	 * 
	 * @param domRequest
	 * @return
	 */
	public static RequestType unmarshallRequest(Element domRequest) {
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

	/**
	 * Marshall from JAXB RequestType in SunXACML to DOM Element
	 * 
	 * @param sunxacmlRequest
	 * @return
	 */
	public static Element marshall(
			oasis.names.tc.xacml._2_0.context.schema.os.RequestType sunxacmlRequest) {
		
		JAXBElement<RequestType> jaxbRequest = (new ObjectFactory()).createRequest(sunxacmlRequest);
		
		Element element = null;
		try {
			element = marshall(RequestType.class, jaxbRequest);
		} catch (JAXBException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();			
		} catch (ParserConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return element;
	}
	
	/**
	 * Marshall a generic JAXBElement to DOM Element
	 * 
	 * @param <T>
	 * @param cls
	 * @param jaxbObject
	 * @return
	 * @throws JAXBException
	 * @throws ParserConfigurationException 
	 */
	private static <T> Element marshall(Class<T> cls, JAXBElement<T> jaxbObject) throws JAXBException, ParserConfigurationException {
		JAXBContext jc = JAXBContext.newInstance(cls);
		Marshaller marshaller = jc.createMarshaller();

		marshaller.setProperty(javax.xml.bind.Marshaller.JAXB_FORMATTED_OUTPUT,
				   new Boolean(true));
		
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);

		DocumentBuilder db = dbf.newDocumentBuilder();		
		Document doc = db.newDocument();
		
		marshaller.marshal(jaxbObject, doc);
		
		return doc.getDocumentElement();
	}

	/**
	 *  Convert OpenSAML XACML ResponseType object to SunXACML ResponseCtx 
	 *  
	 * @param xacmlResponse
	 * @return
	 */
	public static ResponseCtx convert2ResponseCtx(ResponseType xacmlResponse) {
		
		
		try {
			Element domResponse = OpenSAMLHelper.marshall(xacmlResponse);
			String xmlValue = XMLHelper.marshalDOMElement(domResponse);
			
			// unmarshall to ResponseCtx object
			ByteArrayInputStream bis = new ByteArrayInputStream(xmlValue.getBytes());
			ResponseCtx responseCtx = ResponseCtx.getInstance(bis);
			
			return responseCtx;
			
		} catch (MarshallingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ParsingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;
	}
}

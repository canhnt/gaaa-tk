/**
 * 
 */
package org.aaaarch.sunxacml.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.aaaarch.util.OpenSAMLUtil;
import org.aaaarch.xmltooling.XMLHelper;
import org.opensaml.xacml.ctx.ResponseType;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

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
public class SunXACMLUtil {
	
	/**
	 * Convert from org.opensaml.xacml.ctx.RequestType in OpenSAML to 
	 * oasis.names.tc.xacml._2_0.context.schema.os.RequestType in SunXACML
	 * 
	 * @param xacmlRequestOpenSAML
	 * @return
	 */
	public static oasis.names.tc.xacml._2_0.context.schema.os.RequestType convertRequest(
			org.opensaml.xacml.ctx.RequestType xacmlRequestOpenSAML) {
		
		Element element;
		
		try {
			element = OpenSAMLUtil.marshal(xacmlRequestOpenSAML);
			return unmarshall(oasis.names.tc.xacml._2_0.context.schema.os.RequestType.class, element);
		} catch (MarshallingException e) {
			e.printStackTrace();			
		}		
		return null;
	}

	/**
	 * Unmarshall from DOM Element to a generic JAXBElement
	 * 
	 * @param <T>
	 * @param cls
	 * @param domRequest
	 * @return
	 */
	private static <T> T unmarshall(Class<T> cls,
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
		
		JAXBElement<oasis.names.tc.xacml._2_0.context.schema.os.RequestType> jaxbRequest = (new ObjectFactory()).createRequest(sunxacmlRequest);
		
		Element element = null;
		try {
			element = marshall(oasis.names.tc.xacml._2_0.context.schema.os.RequestType.class, jaxbRequest);
		} catch (JAXBException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();			
		} catch (ParserConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return element;
	}
	
	public static Element marshal(
			oasis.names.tc.xacml._2_0.context.schema.os.ResponseType response) {
		JAXBElement<oasis.names.tc.xacml._2_0.context.schema.os.ResponseType> jaxbRequest = (new ObjectFactory()).createResponse(response);
		
		Element element = null;
		try {
			element = marshall(oasis.names.tc.xacml._2_0.context.schema.os.ResponseType.class, jaxbRequest);
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
			Element domResponse = OpenSAMLUtil.marshal(xacmlResponse);
			String xmlValue = XMLHelper.toString(domResponse);
			
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
	
	public static org.opensaml.xacml.ctx.ResponseType convertResponse(oasis.names.tc.xacml._2_0.context.schema.os.ResponseType response) {
		
		Element elementResponse = marshal(response);
		
		try {
			return OpenSAMLUtil.unmarshalResponse(elementResponse);
		} catch (UnmarshallingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * Unmarshal from DOM Element to oasis.names.tc.xacml._2_0.context.schema.os.RequestType
	 * 
	 * @param domRequest
	 * @return
	 */
	public static RequestType unmarshalRequestType(Element domRequest) {
		return unmarshall(RequestType.class, domRequest);
	}

	/**
	 * Read an XACML request file and transform to the RequestType object instance 
	 * @param is
	 * @return
	 * @throws ParserConfigurationException
	 * @throws SAXException
	 * @throws IOException
	 */
	public static RequestType unmarshalRequestType(InputStream is) throws ParserConfigurationException, SAXException, IOException {
		
		Document doc = XMLHelper.readXML(is);
		Element xmlDom = doc.getDocumentElement();
		
		return unmarshalRequestType(xmlDom);		
	}
	
	public static RequestType unmarshalRequestType(String xacmlFileName) throws ParserConfigurationException, SAXException, IOException {
		Document doc = XMLHelper.readXML(xacmlFileName);
		Element xmlDom = doc.getDocumentElement();
		
		return unmarshalRequestType(xmlDom);	
	}
}

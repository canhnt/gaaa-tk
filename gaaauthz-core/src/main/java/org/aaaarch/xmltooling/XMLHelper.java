package org.aaaarch.xmltooling;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

public class XMLHelper {

	public static String toString(Element element) {
		try {
			Transformer transformer = TransformerFactory.newInstance()
					.newTransformer();

			transformer.setOutputProperty(OutputKeys.INDENT, "yes");

			StringWriter buffer = new StringWriter();
			transformer.transform(new DOMSource(element), new StreamResult(
					buffer));

			return buffer.toString();

		} catch (TransformerConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (TransformerFactoryConfigurationError e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (TransformerException e) {
			e.printStackTrace();
		}

		return null;
	}

	public static Element unmarshalDOMElement(String xmlValue)
			throws SAXException, IOException, ParserConfigurationException {

		return unmarshalDOMElement(xmlValue.getBytes());
	}

	public static Element unmarshalDOMElement(byte[] input)
			throws SAXException, IOException, ParserConfigurationException {

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		DocumentBuilder db = dbf.newDocumentBuilder();

		Document doc = db.parse(new ByteArrayInputStream(input));

		return doc.getDocumentElement();
	}
	
	/**
	 * Read input stream into XML Document element
	 * 
	 * @param is
	 * @return
	 * @throws ParserConfigurationException
	 * @throws SAXException
	 * @throws IOException
	 */
	public static Document readXML(InputStream is) throws ParserConfigurationException, SAXException, IOException {
		javax.xml.parsers.DocumentBuilderFactory dbf =
			javax.xml.parsers.DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);

		javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();

		org.w3c.dom.Document doc = db.parse(is);

		return doc;
	}
	
	/**
	 * Read a XML text file to XML Document object
	 *  
	 * @param xmlFile
	 * @return
	 * @throws ParserConfigurationException
	 * @throws SAXException
	 * @throws IOException
	 */
	public static Document readXML(String xmlFile) throws ParserConfigurationException, SAXException, IOException {
		javax.xml.parsers.DocumentBuilderFactory dbf =
			javax.xml.parsers.DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);

		javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();

		org.w3c.dom.Document doc = db.parse(xmlFile);

		return doc;
	}
	
	public static <T> Element marshal(JAXBElement<T> jaxbElement, Class<T> cls) {
		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			DocumentBuilder db = dbf.newDocumentBuilder();
		    Document doc = db.newDocument();
		       
			JAXBContext jaxbContext = JAXBContext.newInstance(cls);
			Marshaller marshaller = jaxbContext.createMarshaller();
			
			marshaller.marshal(jaxbElement, doc);		
			
			return doc.getDocumentElement();
		} catch (JAXBException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ParserConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;
	}
	
	/**
	 * Converting DOM Element object into JAXB OASIS XML Object
	 * @param <T>
	 * @param cls
	 * @param domElement
	 * @return
	 */
	public static <T> T marshal(Class<T> cls, Element domElement) {		
		try {
			JAXBContext jc = JAXBContext.newInstance(cls);
			javax.xml.bind.Unmarshaller unmarshaller = jc.createUnmarshaller();
			JAXBElement<T> jaxbObject = unmarshaller.unmarshal(domElement, cls);
			
			T object = jaxbObject.getValue();
			
			return object;
		} catch (JAXBException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
}

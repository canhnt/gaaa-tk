/**
 * 
 */
package org.aaaarch.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.Set;

import javax.xml.namespace.QName;
import javax.xml.parsers.ParserConfigurationException;

import org.opensaml.Configuration;
import org.opensaml.xacml.XACMLObject;
import org.opensaml.xacml.XACMLObjectBuilder;
import org.opensaml.xacml.ctx.*;
import org.opensaml.xacml.ctx.DecisionType.DECISION;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionQueryType;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionStatementType;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.schema.XSBooleanValue;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import com.sun.xacml.ctx.ResponseCtx;
import com.sun.xacml.ctx.Result;
import com.sun.xacml.ctx.Status;
import com.sun.xacml.ctx.StatusDetail;

/**
 * Convert from SunXACML datatypes to OpenSAML datatypes
 * 
 * @author CanhNT
 *
 */
public class OpenSAMLHelper {

	private static final transient org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(OpenSAMLHelper.class);

	
	/**
	 * Convert from oasis.names.tc.xacml._2_0.context.schema.os.RequestType in SunXACML to
	 * org.opensaml.xacml.ctx.RequestType in OpenSAML
	 * 
	 * @param sunxacmlRequest
	 * @return
	 * @throws UnmarshallingException
	 */
	public static RequestType convertRequest(
			oasis.names.tc.xacml._2_0.context.schema.os.RequestType sunxacmlRequest){
		
		// convert to DOM Element
		Element domElement = SunXACMLHelper.marshall(sunxacmlRequest);
		
		// then from DOM Element to org.opensaml.xacml.ctx.RequestType
		try {
			return unmarshallRequest(domElement);
		} catch (UnmarshallingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Unmarshall DOM element to org.opensaml.xacml.ctx.RequestType
	 * 
	 * @param domRequest
	 * @return
	 * @throws UnmarshallingException
	 */
	public static RequestType unmarshallRequest(Element domRequest) throws UnmarshallingException {
		return unmarshall(domRequest, RequestType.DEFAULT_ELEMENT_NAME);
	}
	
	/**
	 * Unmarshall DOM element to a decestor type of XMLObject in OpenSAML.
	 * 
	 * NOTE: when unmarshall the XACML ResponseType, it throws exceptions. using <link>{@link createFromDOM}</link>
	 * 
	 * @param <T>
	 * @param cls
	 * @param domElement
	 * @param qname
	 * @return
	 * @throws UnmarshallingException
	 */
	private static <T extends XMLObject> T unmarshall(Element domElement, QName qname) throws UnmarshallingException {
		Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(qname);
		
		return (T)unmarshaller.unmarshall(domElement);			
	}

	public static <T extends XACMLObject> T createFromDOM(Element domElement, QName qname) {
		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
		XACMLObjectBuilder<T> builder = (XACMLObjectBuilder<T>) builderFactory.getBuilder(qname);
		
		T object = builder.buildObject();
		object.setDOM(domElement);
		return object;
	}
	/**
	 * Marshall a XACMLObject in OpenSAML to DOM Element
	 * 
	 * @param xacmlObject
	 * @return
	 * @throws MarshallingException
	 */
	public static Element marshall(
			org.opensaml.xacml.XACMLObject xacmlObject) throws MarshallingException {

		MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
		Marshaller marshaller = marshallerFactory.getMarshaller(xacmlObject);
		
		return marshaller.marshall(xacmlObject);
	}

//	/**
//	 * Convert SunXACML ResponseCtx object to OpenSAML XACML ResponseType
//	 * Note: this method does not work with OpenSAML library
//	 * @param responseCtx
//	 * @return
//	 * @throws ParserConfigurationException 
//	 */
//	public static ResponseType convert2ResponseType(ResponseCtx responseCtx){
//		// Currently there is only way to marshall to xml string, then unmarshall back to ResponseType
//		//
//		ResponseType responseType = null;
//		
//		ByteArrayOutputStream out = new ByteArrayOutputStream(); 
//		responseCtx.encode(out);
//				
//		Element domElement;
//		try {
//			domElement = XMLHelper.unmarshalDOMElement(out.toByteArray());
//			log.info("BasicXACMLSAMLPDPImpl.convert:" + 
//					org.opensaml.xml.util.XMLHelper.prettyPrintXML(domElement));
//						
//			responseType = createResponseType(domElement);
//
//		} catch (SAXException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (ParserConfigurationException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}	
//		return responseType;						
//	}

//	private static ResponseType createResponseType(Element domElement) {
//		
//		return createFromDOM(domElement, ResponseType.DEFAULT_ELEMENT_NAME);
//	}
//
//	private static ResponseType unmarshallResponseType(Element domRequest) throws UnmarshallingException {
//		
//		return unmarshall(domRequest, ResponseType.DEFAULT_ELEMENT_NAME);
//	}
	
	public static String printSAMLObject(XMLObject xmlObject)  {
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
	
	public static ResponseType createResponseType(ResponseCtx responseCtx) {
		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
		XACMLObjectBuilder<ResponseType> builder = (XACMLObjectBuilder<ResponseType>) builderFactory.getBuilder(ResponseType.DEFAULT_ELEMENT_NAME);
				
		ResponseType response = builder.buildObject();
				
		Set<com.sun.xacml.ctx.Result> results = responseCtx.getResults();
		if (results == null || results.size() == 0)
			return null;
		
		for(com.sun.xacml.ctx.Result r: results) {
			ResultType result = createResultType(r);
			response.setResult(result);
			break;
		}		

		return response;
	}

	public static ResultType createResultType(Result r) {
		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
		XACMLObjectBuilder<ResultType> builder = (XACMLObjectBuilder<ResultType>) builderFactory.getBuilder(ResultType.DEFAULT_ELEMENT_NAME);
		
		ResultType result = builder.buildObject();
		
		DecisionType decision = createDecisionType(r.getDecision());		
		result.setDecision(decision);
		
		StatusType status = createStatusType(r.getStatus());
		result.setStatus(status);
		
		return result;
	}

	public static StatusType createStatusType(Status s) {
		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
		XACMLObjectBuilder<StatusType> builder = (XACMLObjectBuilder<StatusType>) builderFactory.getBuilder(StatusType.DEFAULT_ELEMENT_NAME);

		StatusType status = builder.buildObject();
		
		List<String> codes = s.getCode();
		if (codes == null || codes.size() == 0)
			return null;
		
		String code = codes.get(0);
				
		status.setStatusCode(createStatusCodeType(code));
		status.setStatusDetail(createStatusDetailType(s.getDetail()));
		status.setStatusMessage(createStatusMessageType(s.getMessage()));
		
		return status;
	}
				
	private static StatusMessageType createStatusMessageType(String message) {
		if (message == null)
			return null;
		
		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
		XACMLObjectBuilder<StatusMessageType> builder = (XACMLObjectBuilder<StatusMessageType>) builderFactory.getBuilder(StatusMessageType.DEFAULT_ELEMENT_NAME);

		StatusMessageType statusMessage = builder.buildObject();
		statusMessage.setValue(message);
		return statusMessage;
	}

	private static StatusDetailType createStatusDetailType(StatusDetail d) {
		if (d == null)
			return null;
		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
		XACMLObjectBuilder<StatusDetailType> builder = (XACMLObjectBuilder<StatusDetailType>) builderFactory.getBuilder(StatusDetailType.DEFAULT_ELEMENT_NAME);

		 StatusDetailType statusDetail = builder.buildObject();
		 
		 Element element = d.getDetail().getOwnerDocument().getDocumentElement();
		 statusDetail.setDOM(element);
		
		return statusDetail;
		
	}

	private static StatusCodeType createStatusCodeType(String code) {
		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
		XACMLObjectBuilder<StatusCodeType> builder = (XACMLObjectBuilder<StatusCodeType>) builderFactory.getBuilder(StatusCodeType.DEFAULT_ELEMENT_NAME);
		
		StatusCodeType statusCode = builder.buildObject();
		
		statusCode.setValue(code);
		
		return statusCode;
	}	

	public static DecisionType createDecisionType(int d) {
		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
		XACMLObjectBuilder<DecisionType> builder = (XACMLObjectBuilder<DecisionType>) builderFactory.getBuilder(DecisionType.DEFAULT_ELEMENT_NAME);
		
		DecisionType decision = builder.buildObject();
		
		switch(d) {
			case Result.DECISION_PERMIT:
				decision.setDecision(DECISION.Permit);
				break;
			case Result.DECISION_DENY:
				decision.setDecision(DECISION.Deny);
				break;
			case Result.DECISION_INDETERMINATE:
				decision.setDecision(DECISION.Indeterminate);
				break;
			case Result.DECISION_NOT_APPLICABLE:
				decision.setDecision(DECISION.NotApplicable);
				break;				
		}
				
		return decision;
	}

	public static XACMLAuthzDecisionStatementType createXADS(
			XACMLAuthzDecisionQueryType authzQuery, ResponseType xacmlResponse) {

		if (authzQuery == null)
			throw new NullPointerException("The authzQuery argument must not be null");
	
		if (xacmlResponse == null)
			throw new NullPointerException("The xacmlResponse argument must not be null");
			
		RequestType xacmlRequest = authzQuery.getRequest();
		
		if (xacmlRequest == null)
			throw new IllegalArgumentException("The authzQuery argument does not contains XACML Request");
		
		// create a XACMLAuthzDecisionStatement & insert the xacml response to it
		XACMLAuthzDecisionStatementType authzStatement = createXMLObject(XACMLAuthzDecisionStatementType.class, 
				XACMLAuthzDecisionStatementType.DEFAULT_ELEMENT_NAME_XACML20);
		
		authzStatement.setResponse(xacmlResponse);
		
		// if the ReturnContext in the request is "true", the response MUST include the xacml-context request
		XSBooleanValue isReturnCtx = authzQuery.getReturnContextXSBooleanValue();				
		
		if (isReturnCtx != null && isReturnCtx.getValue()) {
			// include the xacml-context:Request to response
			xacmlRequest.detach();
			authzStatement.setRequest(xacmlRequest);
		}
		
		return authzStatement;
	}
	
	@SuppressWarnings("unchecked")
	public static <T> T createXMLObject (Class<T> cls, QName qname)
    {
        return (T) ((XMLObjectBuilder) 
            Configuration.getBuilderFactory ().getBuilder (qname))
                .buildObject (qname);
    }
		
}

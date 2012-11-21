/**
 * 
 */
package org.aaaarch.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Set;

import javax.xml.namespace.QName;
import javax.xml.parsers.ParserConfigurationException;

import org.aaaarch.sunxacml.util.SunXACMLUtil;
import org.aaaarch.xmltooling.XMLHelper;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
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
import org.opensaml.xml.schema.XSString;
import org.w3c.dom.Document;
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
public class OpenSAMLUtil {

	/**
	 * Convert from oasis.names.tc.xacml._2_0.context.schema.os.RequestType in SunXACML to
	 * org.opensaml.xacml.ctx.RequestType in OpenSAML
	 * 
	 * @param sunxacmlRequest
	 * @return
	 * @throws UnmarshallingException
	 */
	public static RequestType convertRequest(
			oasis.names.tc.xacml._2_0.context.schema.os.RequestType sunxacmlRequest) throws UnmarshallingException{
		
		// convert to DOM Element
		Element domElement = SunXACMLUtil.marshall(sunxacmlRequest);
		
		// then from DOM Element to org.opensaml.xacml.ctx.RequestType
		return unmarshalRequest(domElement);
	}

	/**
	 * Unmarshall DOM element to org.opensaml.xacml.ctx.RequestType
	 * 
	 * @param elementRequest
	 * @return
	 * @throws UnmarshallingException
	 */
	public static RequestType unmarshalRequest(Element elementRequest) throws UnmarshallingException {
		return unmarshall(elementRequest, RequestType.DEFAULT_ELEMENT_NAME);
	}
	
	/**
	 * Unmarshall DOM element to org.opensaml.xacml.ctx.ResponseType
	 * 
	 * @param elementResponse
	 * @return
	 * @throws UnmarshallingException
	 */
	public static ResponseType unmarshalResponse(Element elementResponse) throws UnmarshallingException {
		return unmarshall(elementResponse, ResponseType.DEFAULT_ELEMENT_NAME);
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

	private static <T extends XACMLObject> T createFromDOM(Element domElement, QName qname) {
		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
		XACMLObjectBuilder<T> builder = (XACMLObjectBuilder<T>) builderFactory.getBuilder(qname);
		
		T object = builder.buildObject();
		object.setDOM(domElement);
		return object;
	}
	/**
	 * Marshal a OpenSAML XACMLObject to DOM Element
	 * 
	 * @param xacmlObject
	 * @return
	 * @throws MarshallingException
	 */
	public static Element marshal(
			org.opensaml.xacml.XACMLObject xacmlObject) throws MarshallingException {

		MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
		Marshaller marshaller = marshallerFactory.getMarshaller(xacmlObject);
		
		return marshaller.marshall(xacmlObject);
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
	private static <T> T createXMLObject (Class<T> cls, QName qname)
    {
        return (T) ((XMLObjectBuilder) 
            Configuration.getBuilderFactory ().getBuilder (qname))
                .buildObject (qname);
    }

	/**
	 * Unmarshal DOM Element to XACMLAuthzDecisionQueryType type
	 * 
	 * @param element
	 * @return
	 * @throws UnmarshallingException 
	 */
	public static XACMLAuthzDecisionQueryType unmarshalXADQ(Element element) throws UnmarshallingException {

		Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(XACMLAuthzDecisionQueryType.DEFAULT_ELEMENT_NAME_XACML20);

		XACMLAuthzDecisionQueryType xadq = (XACMLAuthzDecisionQueryType) unmarshaller.unmarshall(element);
		
		return xadq;
	}
	
	public static XACMLAuthzDecisionQueryType unmarshalXADQ(InputStream is) throws ParserConfigurationException, SAXException, IOException, UnmarshallingException {
		Document doc = XMLHelper.readXML(is);
		return unmarshalXADQ(doc.getDocumentElement());
	}
	
	public static XACMLAuthzDecisionQueryType unmarshalXADQ(String filename) throws ParserConfigurationException, SAXException, IOException, UnmarshallingException {
		Document doc = XMLHelper.readXML(filename);
		return unmarshalXADQ(doc.getDocumentElement());
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
	
	/**
	 * Return the boolean value of authorization decision inside the
	 * XACMLAuthzDecisionStatement response
	 * 
	 * @param xacmlAuthzDecisionStatement
	 * @return
	 */
	public static boolean getDecisionValue(
			XACMLAuthzDecisionStatementType xacmlAuthzDecisionStatement) {

		if (xacmlAuthzDecisionStatement == null) {
			throw new NullPointerException("xads argument must not be null");
		}

		ResponseType response = xacmlAuthzDecisionStatement.getResponse();

		ResultType result = response.getResult();
		if (result == null) {
			throw new RuntimeException("No ResultType found in the XACML response: " + 
					OpenSAMLUtil.toString(xacmlAuthzDecisionStatement));

		}

		DecisionType decision = result.getDecision();

		if (decision == null) {
			throw new RuntimeException("No Decision found in the XACML response:" + 
					OpenSAMLUtil.toString(xacmlAuthzDecisionStatement));
		}

		DECISION decisionValue = decision.getDecision();

		if (decisionValue == DECISION.Permit) {
			return true;
		} else if (decisionValue == DECISION.Deny) {
			return false;
		} else if (decisionValue == DECISION.Indeterminate
				|| decisionValue == DECISION.NotApplicable) {
//			log.error("Decision value is not consistent due to no defined policies");
			return false;
		}

		return false;
	}

	public static String getSAMLAttributeValue(Assertion samlAssertion,
			String samlAttributeName) {

		List<Attribute> attributes = samlAssertion.getAttributeStatements()
				.get(0).getAttributes();

		if (attributes == null || attributes.size() == 0)
			return null;

		for (Attribute attr : attributes) {
			if (attr.getName().compareToIgnoreCase(samlAttributeName) == 0) {
				XSString attrValue = (XSString) attr.getAttributeValues()
						.get(0);
				return attrValue.getValue();
			}
		}
		return null;
	}
	
}

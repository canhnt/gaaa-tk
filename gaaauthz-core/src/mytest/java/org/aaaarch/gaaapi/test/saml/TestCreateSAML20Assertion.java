package org.aaaarch.gaaapi.test.saml;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.aaaarch.utils.HelpersReadWrite;
import org.aaaarch.utils.HelpersXMLsecurity;

import org.w3c.dom.Document;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xml.security.Init;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.Namespace;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.encryption.EncryptedData;
import org.opensaml.xml.encryption.impl.EncryptedDataBuilder;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.validation.ValidationException;
import org.joda.time.DateTime;

import org.opensaml.common.impl.RandomIdentifierGenerator;
import org.opensaml.saml2.core.Action;
import org.opensaml.saml2.core.Advice;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.AuthzDecisionStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.DOMPolicy;
import org.opensaml.saml2.core.DOMRequest;
import org.opensaml.saml2.core.DOMResponse;
import org.opensaml.saml2.core.DecisionTypeEnumeration;
import org.opensaml.saml2.core.EncryptedID;
import org.opensaml.saml2.core.Evidence;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.SubjectLocality;
import org.opensaml.saml2.core.XACMLPolicy;
import org.opensaml.saml2.core.XACMLPolicySet;
import org.opensaml.saml2.core.XACMLPolicyStatement;
//import org.opensaml.saml2.core.TestResponse;
import org.opensaml.saml2.core.XACMLAuthzDecisionStatement;
//import org.opensaml.saml2.core.XACMLDecision;
import org.opensaml.saml2.core.XACMLRequest;
import org.opensaml.saml2.core.XACMLResponse;

import org.opensaml.saml2.core.impl.ActionBuilder;
import org.opensaml.saml2.core.impl.AdviceBuilder;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.AssertionImpl;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml2.core.impl.AudienceRestrictionBuilder;
import org.opensaml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.saml2.core.impl.AuthnStatementBuilder;
import org.opensaml.saml2.core.impl.AuthzDecisionStatementBuilder;
import org.opensaml.saml2.core.impl.ConditionsBuilder;
import org.opensaml.saml2.core.impl.EncryptedIDBuilder;
import org.opensaml.saml2.core.impl.EvidenceBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationDataBuilder;
import org.opensaml.saml2.core.impl.SubjectLocalityBuilder;
import org.opensaml.saml2.core.impl.XACMLAuthzDecisionStatementBuilder;
import org.opensaml.saml2.core.impl.XACMLPolicyBuilder;
import org.opensaml.saml2.core.impl.XACMLPolicySetBuilder;
import org.opensaml.saml2.core.impl.XACMLPolicyStatementBuilder;
import org.opensaml.saml2.core.impl.XACMLRequestBuilder;
import org.opensaml.saml2.core.impl.XACMLResponseBuilder;
import org.opensaml.security.SAMLSignatureProfileValidator;

import org.aaaarch.gaaapi.test.saml.SimplePDP;


/**
 * @author Yuri Demchenko
 *
 * 26/07/2007 => SAML2.0 
 */
public class TestCreateSAML20Assertion {
	
	static String outdir = "x-output/";
	static String filename = null;

	// Some init stuff to be placed here
	public static SimplePDP simplePDP = null;
	public static String dirXacmlData = "_aaadata/tmp/xacmldata/";
	
	/*
	 * @Returns an AssertionImpl with components and attributes
	 * Statement = AuthnStatement
	 */
	public static AuthnStatement statementAuthn(){
		/* Get Builder */
		// Get the builder factory
		XMLObjectBuilderFactory builderFactory = org.opensaml.xml.Configuration.getBuilderFactory();
		
		
		AuthnStatementBuilder authnstatement = (AuthnStatementBuilder) 
		builderFactory.getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
		
		SubjectLocalityBuilder subjectlocality = (SubjectLocalityBuilder) 
		builderFactory.getBuilder(SubjectLocality.DEFAULT_ELEMENT_NAME);
		
		AuthnContextBuilder authncontext = (AuthnContextBuilder) 
		builderFactory.getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME);
		
		//DateTime NotBefore and NotOnOrAfter
		//Default Authentication validity 60 min;
		
		DateTime authninstant = new DateTime();
		DateTime sessionnotonorafter = new DateTime(authninstant.plusMinutes(60));
		
		
		//AuthnStatement
		AuthnStatement objectauthnstatement = authnstatement.buildObject();
		
		objectauthnstatement.setSessionIndex("IdPSessionIndex");
		objectauthnstatement.setAuthnInstant(authninstant);
		
		objectauthnstatement.setSessionNotOnOrAfter(sessionnotonorafter);
			SubjectLocality objectlocality = subjectlocality.buildObject();
			objectlocality.setAddress("202.135.105.101");
			objectlocality.setDNSName("voodoo.keuken.nifhef.nl");
			AuthnContext objectauthncontext = authncontext.buildObject();
		
		//TODO AuthnContext/AuthnContextDecl/"AuthnLevelOf Insurance"
		
			
		objectauthnstatement.setSubjectLocality(objectlocality);
		objectauthnstatement.setAuthnContext(objectauthncontext);
		
		return objectauthnstatement;
	}

	public static AssertionImpl createSAML20Assertion(AuthzDecisionStatement objectStatement){
		
		XMLObjectBuilderFactory builderFactory = org.opensaml.xml.Configuration.getBuilderFactory();
		
		// Get builders for Assertion, Issuer, Subject, NameID, Statement ...
		AssertionBuilder assertion = (AssertionBuilder)
		builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);

		IssuerBuilder issuer = (IssuerBuilder)
		builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);

		SubjectBuilder subject = (SubjectBuilder)
		builderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
		
		NameIDBuilder nameid = (NameIDBuilder)
		builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
		
		EncryptedIDBuilder encryptedid = (EncryptedIDBuilder)
		builderFactory.getBuilder(EncryptedID.DEFAULT_ELEMENT_NAME);
		
		EncryptedDataBuilder encrypteddata = (EncryptedDataBuilder)
		builderFactory.getBuilder(EncryptedData.DEFAULT_ELEMENT_NAME);
		
		SubjectConfirmationBuilder subjectconfirmation = (SubjectConfirmationBuilder)
		builderFactory.getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
		
		SubjectConfirmationDataBuilder subjectconfirmationdata = (SubjectConfirmationDataBuilder)
		builderFactory.getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
		
		ConditionsBuilder conditions = (ConditionsBuilder)
		builderFactory.getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
		
		AudienceRestrictionBuilder audiencerestriction = (AudienceRestrictionBuilder)
		builderFactory.getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME);
		
		AdviceBuilder advice = (AdviceBuilder) 
		builderFactory.getBuilder(Advice.DEFAULT_ELEMENT_NAME);		
		
		//AssertionImpl objectassertion = AuthzDecisionStatement();

		///
		
		// DateTime NotBefore and NotOnOrAfter 
		// default valid for 24 hours
		//DateTime notbefore = new DateTime(2007,07,23,0,0,0,0);
		
		DateTime notbefore = new DateTime();
		DateTime notoronafter = new DateTime();
		notoronafter = new DateTime(notbefore.plusHours(24));

		
		/* Build Objects*/
		// Build an Assertion object, Issuer object
		AssertionImpl objectassertion = (AssertionImpl) assertion.buildObject();

		// Issuer
		Issuer objectissuer = issuer.buildObject();
		objectissuer.setNameQualifier("Name Qualifier");
		objectissuer.setSPNameQualifier("SPName Qualifier");
		objectissuer.setFormat("Format");
		objectissuer.setSPProvidedID("SPProvided ID");
		
		// Build the Subject object with attributes BaseID and NameID
		Subject objectsubject = subject.buildObject(); 

		// TODO SAML2.0 Schema allows either NameID or EncryptedID and not both 
			NameID objectnameid = nameid.buildObject();
			objectnameid.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
			objectnameid.setSPNameQualifier("egee:jra1:subject:researcher");
			objectnameid.setValue("oscar@jra1.eu-egee.org");
			//
			EncryptedID objectencryptedid = encryptedid.buildObject();
				EncryptedData objectencrypteddata = encrypteddata.buildObject();
				objectencrypteddata.setID("Encrypted Data ID");
				objectencrypteddata.setType("Encrypted Data Type");
				objectencrypteddata.setMimeType("Encrypted Data Mime Type");
				objectencrypteddata.setEncoding("Encrypted Data Encoding");
			objectencryptedid.setEncryptedData(objectencrypteddata);
			//
			SubjectConfirmation objectsubjectconfirmation = subjectconfirmation.buildObject();
			objectsubjectconfirmation.setMethod("saml:2.0:subject:subject-confirmation:authntoken-signed");
				SubjectConfirmationData objectsubjectconfirmationdata = subjectconfirmationdata.buildObject();
				objectsubjectconfirmationdata.setRecipient("Recipient");
				objectsubjectconfirmationdata.setAddress("Address");
				objectsubjectconfirmationdata.setInResponseTo("InResponseTo");
				objectsubjectconfirmationdata.setNotBefore(notbefore);
				objectsubjectconfirmationdata.setNotOnOrAfter(notoronafter);
			objectsubjectconfirmation.setSubjectConfirmationData(objectsubjectconfirmationdata);
		objectsubject.setNameID(objectnameid);	
		objectsubject.setEncryptedID(objectencryptedid);
		objectsubject.getSubjectConfirmations().add(objectsubjectconfirmation); 
		
		// Conditions
		Conditions objectconditions = conditions.buildObject();
		objectconditions.setNotBefore(notbefore);
		objectconditions.setNotOnOrAfter(notoronafter);
		AudienceRestriction objectaudiencerestriction = audiencerestriction.buildObject();
		objectconditions.getAudienceRestrictions().add(objectaudiencerestriction);
			
		//Advice
		Advice objectadvice = advice.buildObject();
		
		
		// Build Assertion object with attributes, Issuer, Subject ...
		objectassertion.setVersion(org.opensaml.common.SAMLVersion.VERSION_20);
		objectassertion.setID("ID");
		DateTime issueinstant = new DateTime();
		//Date startDate = new Date();
		objectassertion.setIssueInstant(issueinstant);
		
		objectassertion.setIssuer(objectissuer);
		objectassertion.setSubject(objectsubject);
		objectassertion.setConditions(objectconditions);
		objectassertion.setAdvice(objectadvice);
		
		//System.out.println("objectStatement.DEFAULT_ELEMENT_NAME = " + objectStatement.DEFAULT_ELEMENT_NAME);
		/*
		if (objectStatement.DEFAULT_ELEMENT_NAME == AuthzDecisionStatement.DEFAULT_ELEMENT_NAME) {
			objectassertion.getAuthzDecisionStatements().add( (AuthzDecisionStatement) objectStatement);	
		}
		if (objectStatement.DEFAULT_ELEMENT_NAME == AuthnStatement.DEFAULT_ELEMENT_NAME) {
			objectassertion.getAuthnStatements().add( (AuthnStatement) objectStatement);	
		}
		if (objectStatement.DEFAULT_ELEMENT_NAME == AttributeStatement.DEFAULT_ELEMENT_NAME) {
			objectassertion.getAttributeStatements().add( (AttributeStatement) objectStatement);	
		}
		*/
		objectassertion.getAuthzDecisionStatements().add(objectStatement);
		
		return objectassertion;
	}	
	public static AssertionImpl createSAML20AssertionBase(){
	
		XMLObjectBuilderFactory builderFactory = org.opensaml.xml.Configuration.getBuilderFactory();
		
		// Get builders for Assertion, Issuer, Subject, NameID, Statement ...
		AssertionBuilder assertion = (AssertionBuilder)
		builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);

		IssuerBuilder issuer = (IssuerBuilder)
		builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);

		SubjectBuilder subject = (SubjectBuilder)
		builderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
		
		NameIDBuilder nameid = (NameIDBuilder)
		builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
		
		EncryptedIDBuilder encryptedid = (EncryptedIDBuilder)
		builderFactory.getBuilder(EncryptedID.DEFAULT_ELEMENT_NAME);
		
		EncryptedDataBuilder encrypteddata = (EncryptedDataBuilder)
		builderFactory.getBuilder(EncryptedData.DEFAULT_ELEMENT_NAME);
		
		SubjectConfirmationBuilder subjectconfirmation = (SubjectConfirmationBuilder)
		builderFactory.getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
		
		SubjectConfirmationDataBuilder subjectconfirmationdata = (SubjectConfirmationDataBuilder)
		builderFactory.getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
		
		ConditionsBuilder conditions = (ConditionsBuilder)
		builderFactory.getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
		
		AudienceRestrictionBuilder audiencerestriction = (AudienceRestrictionBuilder)
		builderFactory.getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME);
		
		AdviceBuilder advice = (AdviceBuilder) 
		builderFactory.getBuilder(Advice.DEFAULT_ELEMENT_NAME);		
		
		//AssertionImpl objectassertion = AuthzDecisionStatement();

		///
		
		// DateTime NotBefore and NotOnOrAfter 
		// default valid for 24 hours
		//DateTime notbefore = new DateTime(2007,07,23,0,0,0,0);
		
		DateTime notbefore = new DateTime();
		DateTime notoronafter = new DateTime();
		notoronafter = new DateTime(notbefore.plusHours(24));

		
		/* Build Objects*/
		// Build an Assertion object, Issuer object
		AssertionImpl objectassertion = (AssertionImpl) assertion.buildObject();

		// Issuer
		Issuer objectissuer = issuer.buildObject();
		objectissuer.setNameQualifier("Name Qualifier");
		objectissuer.setSPNameQualifier("SPName Qualifier");
		objectissuer.setFormat("Format");
		objectissuer.setSPProvidedID("SPProvided ID");
		
		// Build the Subject object with attributes BaseID and NameID
		Subject objectsubject = subject.buildObject(); 

		// TODO SAML2.0 Schema allows either NameID or EncryptedID and not both 
			NameID objectnameid = nameid.buildObject();
			objectnameid.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
			objectnameid.setSPNameQualifier("egee:jra1:subject:researcher");
			objectnameid.setValue("oscar@jra1.eu-egee.org");
			//
			EncryptedID objectencryptedid = encryptedid.buildObject();
				EncryptedData objectencrypteddata = encrypteddata.buildObject();
				objectencrypteddata.setID("Encrypted Data ID");
				objectencrypteddata.setType("Encrypted Data Type");
				objectencrypteddata.setMimeType("Encrypted Data Mime Type");
				objectencrypteddata.setEncoding("Encrypted Data Encoding");
			objectencryptedid.setEncryptedData(objectencrypteddata);
			//
			SubjectConfirmation objectsubjectconfirmation = subjectconfirmation.buildObject();
			objectsubjectconfirmation.setMethod("saml:2.0:subject:subject-confirmation:authntoken-signed");
				SubjectConfirmationData objectsubjectconfirmationdata = subjectconfirmationdata.buildObject();
				objectsubjectconfirmationdata.setRecipient("Recipient");
				objectsubjectconfirmationdata.setAddress("Address");
				objectsubjectconfirmationdata.setInResponseTo("InResponseTo");
				objectsubjectconfirmationdata.setNotBefore(notbefore);
				objectsubjectconfirmationdata.setNotOnOrAfter(notoronafter);
			objectsubjectconfirmation.setSubjectConfirmationData(objectsubjectconfirmationdata);
		objectsubject.setNameID(objectnameid);	
		objectsubject.setEncryptedID(objectencryptedid);
		objectsubject.getSubjectConfirmations().add(objectsubjectconfirmation); 
		
		// Conditions
		Conditions objectconditions = conditions.buildObject();
		objectconditions.setNotBefore(notbefore);
		objectconditions.setNotOnOrAfter(notoronafter);
		AudienceRestriction objectaudiencerestriction = audiencerestriction.buildObject();
		objectconditions.getAudienceRestrictions().add(objectaudiencerestriction);
			
		//Advice
		Advice objectadvice = advice.buildObject();
		
		
		// Build Assertion object with attributes, Issuer, Subject ...
		objectassertion.setVersion(org.opensaml.common.SAMLVersion.VERSION_20);
		
		// Randon identifier
		RandomIdentifierGenerator rid = new RandomIdentifierGenerator();
		String randomID = rid.generateIdentifier();
		objectassertion.setID(randomID);
		DateTime issueinstant = new DateTime();
		
		//Date startDate = new Date();
		objectassertion.setIssueInstant(issueinstant);
		
		objectassertion.setIssuer(objectissuer);
		objectassertion.setSubject(objectsubject);
		objectassertion.setConditions(objectconditions);
		objectassertion.setAdvice(objectadvice);
		
		//System.out.println("objectStatement.DEFAULT_ELEMENT_NAME = " + objectStatement.DEFAULT_ELEMENT_NAME);
		/*
		if (objectStatement.DEFAULT_ELEMENT_NAME == AuthzDecisionStatement.DEFAULT_ELEMENT_NAME) {
			objectassertion.getAuthzDecisionStatements().add( (AuthzDecisionStatement) objectStatement);	
		}
		if (objectStatement.DEFAULT_ELEMENT_NAME == AuthnStatement.DEFAULT_ELEMENT_NAME) {
			objectassertion.getAuthnStatements().add( (AuthnStatement) objectStatement);	
		}
		if (objectStatement.DEFAULT_ELEMENT_NAME == AttributeStatement.DEFAULT_ELEMENT_NAME) {
			objectassertion.getAttributeStatements().add( (AttributeStatement) objectStatement);	
		}
		*/
		//objectassertion.getAuthzDecisionStatements().add(objectStatement);
		
		return objectassertion;
	}
	/*
	 * @Returns an AssertionImpl with components and attributes
	 * Statement = AuthzDecisionStatement
	 */
	public static AuthzDecisionStatement statementAuthzDecision(){
		/* Get Builder */
		// Get the builder factory
		XMLObjectBuilderFactory builderFactory = org.opensaml.xml.Configuration.getBuilderFactory();
		
		// AuthzDecisionStatement
		
		AuthzDecisionStatementBuilder authzstatement = (AuthzDecisionStatementBuilder) 
				builderFactory.getBuilder(AuthzDecisionStatement.DEFAULT_ELEMENT_NAME);
		
		
		//AuthzDecisionStatement
		// Allows only one Action - this is limitation of the SAML2.0 specification
		AuthzDecisionStatement authzdecisionstatement = authzstatement.buildObject();
		
		authzdecisionstatement.setResource("http://nikhef.nl/VO-EGEE/CE01");
		authzdecisionstatement.setDecision(DecisionTypeEnumeration.PERMIT);
			
		// Set Action: Allows only one Action - this is limitation of the SAML2.0 specification
		ActionBuilder action = (ActionBuilder)
				builderFactory.getBuilder(Action.DEFAULT_ELEMENT_NAME);
		
		Action objectaction = action.buildObject();
		objectaction.setNamespace("urn:oasis:names:tc:SAML:1.0:action:egee");
		objectaction.setAction("urn:oasis:names:tc:SAML:1.0:action:egee:ce:submit-job");
		//objectaction.setAction("urn:oasis:names:tc:SAML:2.0:action:egee:ce:set-vwss");
		authzdecisionstatement.getActions().add(objectaction); 
		
		// Evidence - TODO: something is wrong with Evidence
		EvidenceBuilder evidence = (EvidenceBuilder)
				builderFactory.getBuilder(Evidence.DEFAULT_ELEMENT_NAME);
		Evidence objectevidence = evidence.buildObject();
		//objectevidence.addNamespace(new Namespace());
		//objectevidence.setDOM();
		Namespace nsev = new Namespace();
		nsev.setNamespaceURI("urn:oasis:names:tc:SAML:1.0:action:egee:");
		//authzdecisionstatement.getEvidence();//.addNamespace(nsev); 
		
		return authzdecisionstatement;
	}
	
	
	/*
	 * @Returns an AssertionImpl with components and attributes
	 * Statement = AttributeStatement
	 */
	public static AttributeStatement statementAttribute(){
		/* Get Builder */
		// Get the builder factory
		XMLObjectBuilderFactory builderFactory = org.opensaml.xml.Configuration.getBuilderFactory();
		
		
		AttributeStatementBuilder attributestatement = (AttributeStatementBuilder) 
		builderFactory.getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
		
		AttributeBuilder attribute = (AttributeBuilder) 
		builderFactory.getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
		
		
		//Attribute Statement
		AttributeStatement objectattributestatement = attributestatement.buildObject();
			Attribute objectattribute = attribute.buildObject();
			objectattribute.setName("Attribute Name");
			objectattribute.setFriendlyName("Friendly Name");
			objectattribute.setNameFormat("Name Format");
		objectattributestatement.getAttributes().add(objectattribute);
				
		return objectattributestatement;
	}
	
	/*
	 * @Returns an AssertionImpl with components and attributes
	 * Statement = StatementXACMLAuthz
	 */
	public static AssertionImpl statementXACMLAuthzDecision() throws Exception{
		/* Get Builder */
		// Get the builder factory
		XMLObjectBuilderFactory builderFactory = org.opensaml.xml.Configuration.getBuilderFactory();
		
		// Get a builder for Assertion, Issuer, Subject, NameID, Statement ...
		//AssertionBuilder assertion = (AssertionBuilder)
		//builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
		//AssertionExtS20X20Builder assertion = (AssertionExtS20X20Builder) builderFactory.getBuilder(AssertionExtS20X20.DEFAULT_ELEMENT_NAME);
		AssertionBuilder assertion = (AssertionBuilder) builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);

		IssuerBuilder issuer = (IssuerBuilder)
		builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);

		XACMLAuthzDecisionStatementBuilder xacmlauthz = (XACMLAuthzDecisionStatementBuilder) 
		builderFactory.getBuilder(XACMLAuthzDecisionStatement.DEFAULT_ELEMENT_NAME);
		
		/* Build Objects*/
		AssertionImpl objectassertion = (AssertionImpl) assertion.buildObject();
		//AssertionExtS20X20Impl objectassertion = (AssertionExtS20X20Impl) assertion.buildObject();

		// Issuer
		Issuer objectissuer = issuer.buildObject();
		objectissuer.setValue("https://XACMLPDP.example.com");
	
		//TODO: Modify Request insertion
		String dirRequest = "x-output/";
		
		String[] requestFile = new String[1];
		requestFile[0] =dirRequest+"IIIF006Request.xml";
		System.out.println("** Using Request file: "+requestFile[0]);
		
		/* Create XML document instance */ 
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		
		// SAML Assertion and XML Signature part need to be namespace aware
		dbf.setNamespaceAware(true);		
		DocumentBuilder db = dbf.newDocumentBuilder();
		
		// Open the request document
		File request = new File(requestFile[0]);
        Document documentXACMLRequest = db.parse(request);

		/* Initialisation of DOMRequest with the XACML Document
		 * From XACMLDocument to DOMDocument*/
		DOMRequest requestDOM = new DOMRequest(documentXACMLRequest);
		
		/*Object XACMLRequest with the DOMRequest element*/
 	   	XACMLRequestBuilder xacmlrequest = (XACMLRequestBuilder) 
  		builderFactory.getBuilder(XACMLRequest.DEFAULT_ELEMENT_NAME);
 	   	XACMLRequest objectxacmlrequest= xacmlrequest.buildObject();
 	   	objectxacmlrequest.setDOM(requestDOM.transformDocument());
		
 	   	/*Add the XACMLResponse/XACMLRequest in the XACMLAuthzDecisionStatement*/
		XACMLAuthzDecisionStatement objectxacmlauthz = xacmlauthz.buildObject();	
		objectxacmlauthz.setRequest(objectxacmlrequest);
		
		
 	   	/*Part SimplePDP with choice : repository or database*/
		simplePDP = new SimplePDP();
		// put the request file as argument to the main program
		simplePDP.main(requestFile);
		
		String[] responseFiles = simplePDP.listXMLDirectory(new File(dirXacmlData),"Response");
		
		/*
		 * 
		 * TODO Only one response (the last response) is written in the xml file
		 * 
		 */
		System.out.println("\nResponse (Decision = PERMIT) :");
		for(int i = 0;i<responseFiles.length; i++){
		System.out.println(responseFiles[i]);
		
		// Open the response document
		File response = new File(responseFiles[i]);
	    Document XACMLDocumentResponse = db.parse(response);
		
		/* Initialisation of DOMResponse with the XACML Document
		 * From XACMLDocument to DOMDocument*/
		DOMResponse responseDOM = new DOMResponse(XACMLDocumentResponse);
		
		/*Object XACMLResponse with the DOMResponse element*/
 	   	XACMLResponseBuilder xacmlresponse = (XACMLResponseBuilder) 
  		builderFactory.getBuilder(XACMLResponse.DEFAULT_ELEMENT_NAME);
 	   	XACMLResponse objectxacmlresponse = xacmlresponse.buildObject();
 	   	objectxacmlresponse.setDOM(responseDOM.transformDocument());

 	   	objectxacmlauthz.setResponse(objectxacmlresponse);
		}
 	   	
		// Build AssertionImpl object with attributes, Issuer, Subject ...
		objectassertion.setVersion(org.opensaml.common.SAMLVersion.VERSION_20);
		objectassertion.setID("98123676");
		DateTime issueinstant = new DateTime(2007,07,23,0,0,0,0);
		objectassertion.setIssueInstant(issueinstant);
		
		objectassertion.setIssuer(objectissuer);
		//objectassertion.setXACMLAuthzDecisionStatement(objectxacmlauthz);
		objectassertion.getStatements().add(objectxacmlauthz);
		//objectassertion.getStatements().add(objectxacmlauthz[2]);
		
		return objectassertion;
	}
	
	
	/*
	 * @Returns an AssertionImpl with components and attributes
	 * Statement = XACMLPolicyStatement
	 */
	public static AssertionImpl statementXACMLPolicy() throws Exception{
		/* Get Builder */
		// Get the builder factory
		XMLObjectBuilderFactory builderFactory = org.opensaml.xml.Configuration.getBuilderFactory();
		
		// Get a builder for Assertion, Issuer, Subject, NameID, Statement ...
		AssertionBuilder assertion = (AssertionBuilder)
		builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);

		IssuerBuilder issuer = (IssuerBuilder)
		builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);

		XACMLPolicyStatementBuilder xacmlpolicy = (XACMLPolicyStatementBuilder) 
		builderFactory.getBuilder(XACMLPolicyStatement.DEFAULT_ELEMENT_NAME);
		
		/* Build Objects*/
		//AssertionExtS20X20Impl objectassertion = (AssertionExtS20X20Impl) assertion.buildObject();
		AssertionImpl objectassertion = (AssertionImpl) assertion.buildObject();

		// Issuer
		Issuer objectissuer = issuer.buildObject();
		objectissuer.setValue("https://XACMLPDP.example.com");
		
		XACMLPolicyStatement objectxacmlpolicy = xacmlpolicy.buildObject();
		
		/* Create XML document instance */ 
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		
		// SAML Assertion and XML Signature part need to be namespace aware
		dbf.setNamespaceAware(true);		
		DocumentBuilder db = dbf.newDocumentBuilder();
			
		/*
		 * 
		 * TODO for all policy/policySet files ant NOT for one (the last one)
		 * 
		 */
		// 0 is to obtain policy files
		String[] policyFiles = splitPolicyFiles(0);
		for(int i = 0 ; i<policyFiles.length; i++){
			if(policyFiles[i] != null){ //if there is no value because String[] too big
				File policyFile = new File(policyFiles[i]);
		        Document XACMLDocumentPolicy = db.parse(policyFile);
		        
				/* Initialisation of DOMPolicy with the XACML Document
				 * From XACMLDocument to DOMDocument */
				DOMPolicy policyDOM = new DOMPolicy(XACMLDocumentPolicy);
				XACMLPolicyBuilder policy = (XACMLPolicyBuilder) 
				builderFactory.getBuilder(XACMLPolicy.DEFAULT_ELEMENT_NAME);
				XACMLPolicy objectpolicy = policy.buildObject();
				objectpolicy.setDOM(policyDOM.transformDocument());
				
				objectxacmlpolicy.setPolicy(objectpolicy);
			}
		}
		
		// 1 is to obtain policySet files
		String[] policySetFiles = splitPolicyFiles(1);
		for(int i = 0 ; i<policySetFiles.length; i++){
			if(policySetFiles[i] != null){//if there is no value because String[] too big
				File policySetFile = new File(policySetFiles[i]);
		        Document XACMLDocumentPolicySet = db.parse(policySetFile);
				/*PolicySet */
				DOMPolicy policySetDOM = new DOMPolicy(XACMLDocumentPolicySet);
				XACMLPolicySetBuilder policyset = (XACMLPolicySetBuilder) 
				builderFactory.getBuilder(XACMLPolicySet.DEFAULT_ELEMENT_NAME);
				XACMLPolicySet objectpolicyset = policyset.buildObject();
				objectpolicyset.setDOM(policySetDOM.transformDocument());
				
				objectxacmlpolicy.setPolicySet(objectpolicyset);
			}
		}
		
		// Build Assertion object with attributes, Issuer, Subject ...
		objectassertion.setVersion(org.opensaml.common.SAMLVersion.VERSION_20);
		objectassertion.setID("98123676");
		DateTime issueinstant = new DateTime(2007,07,23,0,0,0,0);
		objectassertion.setIssueInstant(issueinstant);
		
		objectassertion.setIssuer(objectissuer);
		//objectassertion.setXACMLPolicyStatement(objectxacmlpolicy);
		objectassertion.getStatements().add(objectxacmlpolicy);
		
		return objectassertion;
	}
	
	public static boolean validateSignedAssertion (Assertion signedAssertion) {
		boolean valid = false;
		
		Response response = getResponse();

		SAMLSignatureProfileValidator profileValidator = getSignatureProfileValidator();
		try {
		    profileValidator.validate(response.getSignature());
		} catch (ValidationException e) {
		    // Indicates signature did not conform to SAML Signature profile
		    e.printStackTrace();
		}

		Credential verificationCredential = getVerificationCredential(response);
		SignatureValidator sigValidator = new SignatureValidator(verificationCredential);
		try {
		    sigValidator.validate(response.getSignature());
		} catch (ValidationException e) {
		    // Indicates signature was not cryptographically valid, or possibly a processing error
		    e.printStackTrace();
		return valid;   
	}
		
	}
	
	public static Assertion signAssertion (Assertion assertion) {
		
		Credential signingCredential = getSigningCredential();

		Signature signature = (Signature) Configuration.getBuilderFactory()
		                        .getBuilder(Signature.DEFAULT_ELEMENT_NAME)
		                        .buildObject(Signature.DEFAULT_ELEMENT_NAME);

		signature.setSigningCredential(signingCredential);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		signature.setKeyInfo(getKeyInfo(signingCredential));

		assertion.setSignature(signature);

		try {
		    Configuration.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
		} catch (MarshallingException e) {
		    e.printStackTrace();
		}

		try {
		    Signer.signObject(signature);
		} catch (SignatureException e) {
		    e.printStackTrace();
		}
		
		
		return assertion;
	}
	
	// Marshall SAML object to DOM document
	public static Document marshallAssertionObject (AssertionImpl objectAssertion) throws Exception {

		/* Create XML document instance */ 
		javax.xml.parsers.DocumentBuilderFactory dbf =
			javax.xml.parsers.DocumentBuilderFactory.newInstance();
		
		// SAML Assertion and XML Signature part need to be namespace aware
		dbf.setNamespaceAware(true);		
		javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
		
		// Create a new document
		Document doc = db.newDocument();

		MarshallerFactory marshallerFactory =
			org.opensaml.xml.Configuration.getMarshallerFactory();
	
		// Get the Assertion marshaller
		Marshaller marshaller = marshallerFactory.getMarshaller(objectAssertion);
		
		// Marshall the Assertion  
		marshaller.marshall(objectAssertion, doc);
		
		return doc;
	}

	//////////// utils
	
	public static org.w3c.dom.Document readFileToDOM (String filename) throws Exception {
	    // start xml document processing part
	    javax.xml.parsers.DocumentBuilderFactory dbf =
	       javax.xml.parsers.DocumentBuilderFactory.newInstance();

	    //XML Signature needs to be namespace aware
	    dbf.setNamespaceAware(true);

	    javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
	    //org.w3c.dom.Document docnew = db.newDocument();

	    // reading document
	    System.out.print("file to read " + filename + "\n");
	    org.w3c.dom.Document doc = db.parse(filename);

	    return doc;
	}	
	
	// Print DOM document
	public static void printDOMdoc(org.w3c.dom.Document doc) throws Exception {
		System.out.println("***** Print Doc *****");
		ByteArrayOutputStream f = new ByteArrayOutputStream();
		XMLUtils.outputDOMc14nWithComments(doc, f);
		f.close();
		System.out.print(f);
	}
	
	// Print DOM document
	public static void printDOMdoc(org.w3c.dom.Document doc, String name) throws Exception {
		System.out.println("\n*** Document : " + name + " ***\n");
		ByteArrayOutputStream f = new ByteArrayOutputStream();
		XMLUtils.outputDOMc14nWithComments(doc, f);
		f.close();
		System.out.print(f+"\n");
	}
	
	// Save DOM Document in a filename 
	public static void saveDOMdoc(org.w3c.dom.Document doc, String filename)
	throws Exception {
		FileOutputStream f = new FileOutputStream(filename);
		XMLUtils.outputDOMc14nWithComments(doc, f);
		f.close();
		System.out.println("\n***** Wrote echo DOM doc to " + filename+" *****");
	}
	
	// Split the policy and policySet
	// TYPE = 0 => return Policy
	// TYPE = 1 => return PolicySet
	public static String[] splitPolicyFiles(int type) throws Exception{
		
		/* Create XML document instance */ 
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		
		// SAML Assertion and XML Signature part need to be namespace aware
		dbf.setNamespaceAware(true);		
		DocumentBuilder db = dbf.newDocumentBuilder();
		
		String[] policyFiles = simplePDP.listXMLDirectory(new File(dirXacmlData),"Policy.xml");
		
		// Creation of the String[] with a dimension too big 
		String [] data = new String[policyFiles.length]; 
		int t = 0;
		for(int i = 0;i<policyFiles.length; i++){
		// Open the policy document 
		File policyFile = new File(policyFiles[i]);
        Document XACMLDocumentPolicy = db.parse(policyFile);
        
        // Get the first child
        String firstChild = XACMLDocumentPolicy.getFirstChild().getNodeName();
        
				if(firstChild.equals("Policy")){
					if(type == 0)
						data[t] = policyFiles[i];
				}
				if(firstChild.equals("PolicySet")){
					if(type == 1)
						data[t] = policyFiles[i];
				}
		}
		return data;
	}
	
	
	public static void main(String[] args) throws Exception{
	//Initialisation
	//org.apache.xml.security.Init.init();
	org.opensaml.DefaultBootstrap.bootstrap();
	
	
	try{
		System.out.println("*** Create, Sign, Validate different types of SAML 2.0 Assertions (with OpenSAML2 library) ***");
		System.out.println("Select assertion type :\n" +
				"1 - AuthN Statement Assertion\n" +
				"2 - AuthZ Decision Statement Assertion\n" +
				"3 - Attribute Assertion\n" +
				"4 - Statement XACML Authz Decision and XACML Authz Policy\n" +
				"6 - Read SAML2 Assertion and print information\n" +
				"7 - Sign SAML Assertion\n" +
				"8 - Validate signed SAML Assertion\n" +
				"");
		int s = HelpersReadWrite.readStdinInt();
		
		switch(s) {
			case 1: {
			//AssertionImpl objectAuthnAssertion = AuthnStatement();
			//Document doc = marshallAssertionObject (objectAuthnAssertion);
			
			AuthnStatement	authnstatement = statementAuthn();
			AssertionImpl objectAuthnAssertion = createSAML20AssertionBase();
			objectAuthnAssertion.getAuthnStatements().add(authnstatement);
			Document doc = marshallAssertionObject (objectAuthnAssertion);

			filename = "saml20assertion-authn01.xml";
			printDOMdoc(doc);
			saveDOMdoc(doc,outdir+filename);
			
			return;
			}
			
			case 2: {
			AuthzDecisionStatement	authzdecisionstatement = statementAuthzDecision();
			AssertionImpl objectAuthzAssertion = createSAML20AssertionBase();
			objectAuthzAssertion.getAuthzDecisionStatements().add(authzdecisionstatement);
			
			Document doc = marshallAssertionObject (objectAuthzAssertion);
			filename = "saml20assertion-authz01.xml";
			printDOMdoc(doc);
			saveDOMdoc(doc,outdir+filename);
			return;
			}
			
			case 3: {
			//AttributeStatement	attrstatement = attributeStatement();
			//AssertionImpl objectAttrAssertion = createSAML20Assertion(attrstatement);
				
			//Document doc = marshallAssertionObjectToDoc (objectAttrAssertion);
			
			filename = "saml20assertion-attr01.xml";
			//printDOMdoc(doc);
			//saveDOMdoc(doc,outdir+filename);
			return;
			}
			
			//XACMLAuthzDecisionStatement
			case 4: {
				/* Create XML document instance */ 
				javax.xml.parsers.DocumentBuilderFactory dbf =
					javax.xml.parsers.DocumentBuilderFactory.newInstance();
				
				// SAML Assertion and XML Signature part need to be namespace aware
				dbf.setNamespaceAware(true);		
				javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
				
				// Create a new document
				Document doc = db.newDocument();
				
				////AssertionImpl objectassertion = StatementXACMLAuthz();
				//AssertionExtS20X20Impl objectassertion = statementXACMLAuthzDecision();
				AssertionImpl objectassertion = statementXACMLAuthzDecision();
							
				// Get the marshaller factory
				MarshallerFactory marshallerFactory =
					org.opensaml.xml.Configuration.getMarshallerFactory();
			
				// Get the Assertion marshaller
				Marshaller marshaller = marshallerFactory.getMarshaller(objectassertion);
				
				// Marshall the Assertion  
				marshaller.marshall(objectassertion, doc);
					
			filename = "saml20assertion-xacml20authz01.xml";
			//printDOMdoc(doc);
			saveDOMdoc(doc,outdir+filename);
			
				objectassertion = statementXACMLPolicy();
				marshaller = marshallerFactory.getMarshaller(objectassertion);
				
				// Marshall the Assertion  
				marshaller.marshall(objectassertion, doc);
			
			filename = "saml20assertion-xacml20policy01.xml";
			//printDOMdoc(doc,"XACMLPolicyStatement");
			saveDOMdoc(doc,outdir+filename);
			
			// dell the tmp document 
			simplePDP.deleteFilesDirectory(new File(dirXacmlData));
			return; }
		case 5: {
			return;	} 	
		case 6: {	
			filename = "saml20assertion-authn01.xml";
			//filename = "saml20assertion-authz01.xml";
			//filename = "saml20assertion-attr01.xml";
   			String localdir = "x-output/";
   			String aztstr = HelpersReadWrite.readFileToString(localdir + filename);
   			System.out.println("\nTestSAML2: Assertion file to read: " + (localdir + filename));
   			Document assertdoc = HelpersReadWrite.readFileToDOM(localdir + filename);
   			HelpersXMLsecurity.printDOMdoc(assertdoc);
   			
			
			return;	}
		case 7: {			
			return;	}
		case 8: {			
			return;	}
		}
	  }
	  catch (Exception e) {
		e.printStackTrace();
		System.exit(1);
	  }
	}	
}
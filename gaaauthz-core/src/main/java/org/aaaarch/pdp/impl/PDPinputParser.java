/*
 * Created on May 23, 2004
 *
 * AIRG at UvA, Collaboratory.nl Project
 * @author Yuri Demchenko
 * AIRG at UvA, Collaboratory.nl Project 
 */
package org.aaaarch.pdp.impl;

import org.aaaarch.config.ConstantsNS;
import org.aaaarch.utils.XmlException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder; 
import javax.xml.parsers.DocumentBuilderFactory;  

import com.sun.xacml.ParsingException;
import com.sun.xacml.ctx.Attribute;
import com.sun.xacml.ctx.RequestCtx;
import com.sun.xacml.ctx.Subject;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.Vector;
import java.io.ByteArrayInputStream;
import java.io.InputStream;

public class PDPinputParser {
	
	private final static String DELIM_URN = ":";
	private final static String DELIM_URL = "/";

    // standard constants for setting schema validation

    private static final String JAXP_SCHEMA_LANGUAGE =
        "http://java.sun.com/xml/jaxp/properties/schemaLanguage";
    
    private static final String W3C_XML_SCHEMA =
        "http://www.w3.org/2001/XMLSchema";

    private static final String JAXP_SCHEMA_SOURCE =
        "http://java.sun.com/xml/jaxp/properties/schemaSource";


	// Parsing XACML RequestCtx to vector of context values 
    // vector context = [subjectId, role, subjctx, actionId, resourceId, subjext]
	public static Vector parseXACMLRequest (String reqString) throws Exception {
		Vector<String> context = new Vector<String>();

		System.out.println("\nPDPinputParser.parseRequest: Request message received\n" + reqString + "\n");
		InputStream input = new ByteArrayInputStream(reqString.getBytes());
		Document reqdoc = parseInputStream(input); //Request as Document
		
		// using RequestCtx methods from Sun XACML
		/*
		RequestCtx request = RequestCtx. getInstance( input );

			if( request.getSubjects().isEmpty() ) 
			{  
				if( request.getResource().isEmpty() ) 
				{
					if (request.getAction().isEmpty())
					System.out.println( "PDP input Parser: This XACML RequestCtx is empty" );  
				return null;  
				}
			}
			*/
		// get Subjects Set and Subject from XAML RequestCtx	
		  //Set subjset = request.getSubjects();
		  //Subject subject1 = (Subject) subjset.iterator().next();
		  

		// continuing with ordinary XML document parsing 
		// because of burdeneous SunXACML Ctx processing  
		// TODO: move to parseAttributes and XACML Request processing
		//	Node rootNode = getNode(reqdoc, "Request"); //Request as Node

		  String subjectId = null;
		  String subjconfdata = null;
		  String role = null;
		  String subjctx = null;
		  String subjext = null; //Extensitibility attribute for Subject
		  
		  // only one Subject element is supported now. TODO: multiple Subjects processing
		  Element subject = (Element)reqdoc.getElementsByTagName("Subject").item(0);
		  // This is not required with Sun XACML that returns already Subject Set
		  
		  // Parsing Subject with the String tokenizer
		  // TODO: fix problem that tokeniser takes also quotation mark '"'
		  System.out.println("\nPDPinputParser.parseXACMLRequest: parsing in progress\n"); 

	      NodeList nlsubjattr = subject.getElementsByTagName("Attribute");
	        		  
		  for( int i = 0; i < nlsubjattr.getLength(); i++ ) 
		  {  
			  String attrid = nlsubjattr.item(i).getAttributes().getNamedItem("AttributeId").toString();
			  //System.out.println("\nAttributeId@Subject.Attribute = " + attrid);

			  StringTokenizer st = new StringTokenizer (attrid, DELIM_URN, true );

			  while (st.hasMoreTokens()) 
			  {
				  String atom = st.nextToken();
				  if (atom.equals(ConstantsNS.SUBJECT_SUBJECT_ID + "\""))
				  {
					  subjectId = ((Element) nlsubjattr.item(i)).getElementsByTagName("AttributeValue").item(0).getFirstChild().getNodeValue().toString();					  
					  System.out.println("\nSubject subjectId = " + subjectId);
				  }
				  if (atom.equals(ConstantsNS.SUBJECT_CONFDATA + "\""))
				  {
					  subjconfdata = ((Element) nlsubjattr.item(i)).getElementsByTagName("AttributeValue").item(0).getFirstChild().getNodeValue().toString();
					  System.out.println("\nSubject subjconfdata = " + subjconfdata);
				  }
				  if (atom.equals(ConstantsNS.SUBJECT_ROLE + "\""))
				  {
					  role = ((Element) nlsubjattr.item(i)).getElementsByTagName("AttributeValue").item(0).getFirstChild().getNodeValue().toString();
					  System.out.println("Subject role = " + role);
				  }
				  if (atom.equals(ConstantsNS.SUBJECT_CONTEXT + "\""))
				  {
					  subjctx = ((Element) nlsubjattr.item(i)).getElementsByTagName("AttributeValue").item(0).getFirstChild().getNodeValue().toString();
					  System.out.println("Subject subjctx = " + subjctx);
				  }
				  if (atom.equals("subj-ext\""))
				  {
					  subjext = ((Element) nlsubjattr.item(i)).getElementsByTagName("AttributeValue").item(0).getFirstChild().getNodeValue().toString();
				  }
			  }
		  }
		  
		  //\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
		  // retrieve Resource.Attribute.AttributeValue
		  NodeList nlresattr = ((Element)reqdoc.getElementsByTagName("Resource").item(0)).getElementsByTagName("Attribute");
		  String resourceId = ((Element) nlresattr.item(0)).getElementsByTagName("AttributeValue").item(0).getFirstChild().getNodeValue().toString();

		  //\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
		  // retrieve Action and create possible actions list
		  //Node action = reqdoc.getElementsByTagName("Resource").item(0);
		  NodeList nlactattr = ((Element)reqdoc.getElementsByTagName("Action").item(0)).getElementsByTagName("Attribute");

		  String actionId = new String();
		  List<String> actions = new ArrayList<String>();
		  int k = 0;
		
		  for( int i = 0; i < nlactattr.getLength(); i++ ) 
		  {  
			  String attrid = nlactattr.item(i).getAttributes().getNamedItem("AttributeId").toString();
			
			  StringTokenizer st = new StringTokenizer (attrid, DELIM_URN, true );

			  while (st.hasMoreTokens()) 
			  {
				  String atom = st.nextToken();
				  if (atom.equals(ConstantsNS.ACTION_ACTION_ID + "\""))
				  {
					  actionId = ((Element) nlactattr.item(i)).getElementsByTagName("AttributeValue").item(0).getFirstChild().getNodeValue().toString();
					  actions.add(actionId);
					  k++;
					  System.out.println("Action number " + k + " " + actionId);
				  }
			  }
		  }
		
		  // Compose Vector params = {userId, subctx, role, resourceId, action}
		  // TODO multiple roles and multiple actions
		context.addElement(subjectId);
		context.addElement(role);
		context.addElement(subjctx);
		context.addElement(actionId);
		context.addElement(resourceId);
		context.addElement(subjext);
	  
		return context;
		
	}
	
    static Document parseInputStream(InputStream input) throws ParsingException
    {
    	Document doc = null;

    try {
    	DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setIgnoringComments(true);

        DocumentBuilder db = null;

        // default is namespace aware
        //factory.setNamespaceAware(true);
        factory.setNamespaceAware(false);
                
        // placeholder for enabling schema validation
        String validateYes = "";
        
        if (validateYes.equals("")) {
        // currently no validation is enabled
            factory.setValidating(false);

            db = factory.newDocumentBuilder();

        }
        // unless we can include schema file "vparser.schemaFile"
            else {    
            factory.setValidating(true);

            factory.setAttribute(JAXP_SCHEMA_LANGUAGE, W3C_XML_SCHEMA);
            factory.setAttribute(JAXP_SCHEMA_SOURCE, "vparser.schemaFile");
            
            db = factory.newDocumentBuilder();
        }
        //
        doc = db.parse(input);
        
    } catch (Exception e) {
        throw new XmlException("Error when trying to parse Request");
    }
    return doc;
	}
	
    //TODO: make use of this method
    static Node getNode(Document doc, String rootTagName) 
    {
    	NodeList nodes = null;
    	nodes = doc.getElementsByTagName(rootTagName);
        if (nodes.getLength() != 1)
            throw new XmlException("Multiple " + rootTagName + "Type are discovered");

        return nodes.item(0);
    }
    
    //TODO: redesign and make use of this method    
    private static Set parseAttributes(Node root) throws ParsingException {
        Set<Attribute> attrset = new HashSet<Attribute>();

        // extracts all Attributes under Request root elements Subject, Resource, Action, Environment
        NodeList nodes = root.getChildNodes();
        for (int i = 0; i < nodes.getLength(); i++) {
            Node node = nodes.item(i);
            if (node.getNodeName().equals("Attribute"))
            	// com.sun.xacml.ctx.Attribute.
                attrset.add(Attribute.getInstance(node));
        }

        return attrset;
    }

    
}

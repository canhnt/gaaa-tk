/**
 * @author:
 * Thierry DENYS
 * Created: in 2008
 * Last update: july, 31th 2008
 */

package org.aaaarch.gaaapi.test.exist;

import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Vector;

import org.aaaarch.config.ConfigDomainsPhosphorus;
import org.aaaarch.gaaapi.tvs.TVSTable;
import org.aaaarch.utils.HelpersDateTime;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class AdaptorTvsTableToExist {
	
	private static HashMap<String, HashMap<String, Vector<Comparable>>> domainsT = new HashMap<String, HashMap<String, Vector<Comparable>>> ();
	private static String collectionShortAAA = "AAASessionsRepository";

	public static void storeTVSTableInExist (HashMap domainsT) throws Exception {
		//Document tvsTable = null; 

		// start xml document part
        javax.xml.parsers.DocumentBuilderFactory dbf =
           javax.xml.parsers.DocumentBuilderFactory.newInstance();

        //XML Signature needs to be namespace aware
        dbf.setNamespaceAware(false);

        javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
        org.w3c.dom.Document doc = db.newDocument();
        // root element is AuthzToken
        Element root = doc.createElement("TVSTable");
        root.setAttribute("DomainLocal", ConfigDomainsPhosphorus.DOMAIN_PHOSPHORUS_DEFAULT);
        root.appendChild(doc.createTextNode("\n"));
        doc.appendChild(root);

        //Vector sessionCtx = (Vector) ((HashMap) domainsT.get(domainId)).get(gri);

        for (Iterator i=domainsT.keySet().iterator(); i.hasNext();){
        	String domainId = i.next().toString();
        	HashMap domainSessions = (HashMap) domainsT.get(domainId);
        	//System.out.println("\nsubjkey = " + ikey + "; attrvalue = " + entry);   
        
            Element domainEntry = doc.createElement("TVSEntry");
            domainEntry.setAttribute("DomainId", domainId);
            domainEntry.appendChild(doc.createTextNode("\n"));
            root.appendChild(domainEntry);
            
            for (Iterator j=domainSessions.keySet().iterator(); j.hasNext();){
            	String gri = j.next().toString();
            	Vector sessionCtx = (Vector) domainSessions.get(gri);

            	Element sessionCtxElm = doc.createElement("SessionContext");
            	sessionCtxElm.setAttribute("SessionId", gri);
            	sessionCtxElm.appendChild(doc.createTextNode("\n"));
            	domainEntry.appendChild(sessionCtxElm);

        ////////// creating one table line of the SessionContext /////////////
            
        		Date notBefore = (Date) sessionCtx.get(0);
        		Date notOnOrAfter = (Date) sessionCtx.get(1);
        		String actionId = (String) sessionCtx.get(2);
        		String subjectId = (String) sessionCtx.get(3);
        		String subjectRole = (String) sessionCtx.get(4);
        		String subjectContext = (String) sessionCtx.get(5);
        		String resourceId = (String) sessionCtx.get(6);
        		String resourceSource = (String) sessionCtx.get(7);
        		String resourceTarget = (String) sessionCtx.get(8);
        		String keyinfo = (String) sessionCtx.get(9);
            	
        ///  
        Element conditions = doc.createElement("Conditions");        
        
        if ((!(notBefore == null)) && (!(notOnOrAfter == null))) {
            if (!(notBefore == null)) {
            	conditions.setAttribute("NotBefore", HelpersDateTime.datetostring(notBefore));
            }
            if (!(notOnOrAfter == null)) {
            	conditions.setAttribute("NotOnOrAfter", HelpersDateTime.datetostring(notOnOrAfter));
            }
            //conditions.appendChild(doc.createTextNode("\n"));
            //sessionCtx.appendChild(conditions);
            }

        //conditions.appendChild(doc.createTextNode("\n"));
        sessionCtxElm.appendChild(conditions);
        
        // Actions
        Element action = doc.createElement("Action");
        action.appendChild(doc.createTextNode(actionId));
        sessionCtxElm.appendChild(action);
        sessionCtxElm.appendChild(doc.createTextNode("\n"));
        
        // Create Subject and Resource entries

        //<Subject Id="subject"> 
        //	<SubjectId> </SubjectID>
        //	<SubjectRole> </SubjectRole>
        //	<SubjectContext> </SubjectContext>
        //</Subject>
        Element subject = doc.createElement("Subject");
        subject.setAttribute("Id", "subject");
        sessionCtxElm.appendChild(subject);
        sessionCtxElm.appendChild(doc.createTextNode("\n"));

        {
        //Iterator j=subjset.iterator();
        Element subjectid = doc.createElement("SubjectId");
        //String subjid = subjmap.get(ConstantsNS.SUBJECT_SUBJECT_ID).toString();
        subjectid.appendChild(doc.createTextNode(subjectId));
        //
        Element subjrole = doc.createElement("SubjectRole");
        //String roll = subjmap.get(ConstantsNS.SUBJECT_ROLE).toString();
        subjrole.appendChild(doc.createTextNode(subjectRole));
        //
        Element subjctx = doc.createElement("SubjectContext");
        //String sctx = subjmap.get(ConstantsNS.SUBJECT_CONTEXT).toString();
        subjctx.appendChild(doc.createTextNode(subjectContext));
        //
        subject.appendChild(subjectid);
        subject.appendChild(subjrole);
        subject.appendChild(subjctx);
        subject.appendChild(doc.createTextNode("\n"));
        }
        
  		//<Resource>Target resource </Resource>
        Element resource = doc.createElement("Resource");
        sessionCtxElm.appendChild(resource);
        sessionCtxElm.appendChild(doc.createTextNode("\n"));

        {
            //Iterator j=subjset.iterator();
            Element resourceid = doc.createElement("ResourceId");
            //String resourceId = resmap.get(ConstantsNS.RESOURCE_RESOURCE_ID).toString();
            resourceid.appendChild(doc.createTextNode(resourceId));
            //
            Element resourcesource = doc.createElement("ResourceSource");
            //String resourceSource = resmap.get(ConstantsNS.RESOURCE_SOURCE).toString();
            resourcesource.appendChild(doc.createTextNode(resourceSource));
            //
            Element resourcetarget = doc.createElement("ResourceTarget");
            //String resourceTarget = resmap.get(ConstantsNS.RESOURCE_TARGET).toString();
            resourcetarget.appendChild(doc.createTextNode(resourceTarget));
            //
            resource.appendChild(resourceid);
            resource.appendChild(resourcesource);
            resource.appendChild(resourcetarget);
            resource.appendChild(doc.createTextNode("\n"));
        }        

        // KeyInfo //  
        Element keyinfoElm = doc.createElement("KeyInfo");
        String sessionKey = keyinfo;
        if (keyinfo == null) {
        sessionKey = TVSTable.getSessionKey(domainId, gri);
          }
        keyinfoElm.setAttribute("keytype", "public");
        keyinfoElm.appendChild(doc.createTextNode(sessionKey));
        sessionCtxElm.appendChild(keyinfoElm);
        sessionCtxElm.appendChild(doc.createTextNode("\n"));
        
        InitExistDB exist = new InitExistDB();
        System.out.println(domainId);
        if (domainId.matches("http://testbed.ist-phosphorus.eu/viola"))
        {
        	exist.insertAAAtickets(collectionShortAAA+"/violaReservations", (Node) sessionCtxElm, gri, exist);
        }
        else if (domainId.matches("http://testbed.ist-phosphorus.eu/i2cat"))
        {
        	exist.insertAAAtickets(collectionShortAAA+"/i2catReservations", (Node) sessionCtxElm, gri, exist);
        }
        else if (domainId.matches("http://testbed.ist-phosphorus.eu/uclp"))
        {
        	exist.insertAAAtickets(collectionShortAAA+"/uclpReservations", (Node) sessionCtxElm, gri, exist);
        }
        else if (domainId.matches("http://testbed.ist-phosphorus.eu/oscars"))
        {
        	exist.insertAAAtickets(collectionShortAAA+"/oscarsReservations", (Node) sessionCtxElm, gri, exist);
        }
        else if (domainId.matches("http://testbed.ist-phosphorus.eu/drack"))
        {
        	exist.insertAAAtickets(collectionShortAAA+"/drackReservations", (Node) sessionCtxElm, gri, exist);
        }
        else if (domainId.matches("http://testbed.ist-phosphorus.eu/uva"))
        {
        	exist.insertAAAtickets(collectionShortAAA+"/uvaReservations", (Node) sessionCtxElm, gri, exist);
        }
        else
        {
        	exist.insertAAAtickets(collectionShortAAA, (Node) sessionCtxElm, gri, exist);
        }
        //exist.insertAAAtickets(collectionShortAAA, (Node) domainEntry, domainId, exist);
            }
        }
	}

	
	public static boolean storeTVSTableInExist (String domainId, String gri, Vector sessionCtx) throws Exception {
		boolean ok = true;
        HashMap<String, Vector<Comparable>> domainSessions = new HashMap<String, Vector<Comparable>>();
    	
    	//Vector sessionCtx = (Vector) ((HashMap) domainsT.get(domainId)).get(gri); 

    	String domainToReplace = "";
    	String domainToAdd = "";
        for (Iterator i=domainsT.keySet().iterator(); i.hasNext();){
        	String domainKey = i.next().toString();
        	if (domainKey.equals(domainId)) {
        		domainToReplace = domainKey;
        		//TODO: to write to log file
        		System.out.println("\nTVSTable: domain is present in the table");
        	} 
        }
        if (domainToReplace.equals("")) {
    		domainSessions.put(gri, sessionCtx);
            domainsT.put(domainId, domainSessions);
            storeTVSTableInExist(domainsT);
            return true;
    	}
        
        domainSessions = (HashMap) domainsT.get(domainToReplace);
        String griToReplace = "";
        for (Iterator j=domainSessions.keySet().iterator(); j.hasNext();){
        	String griKey = j.next().toString();
        	if (griKey.equals(gri)) {
        		griToReplace = griKey;
        		//TODO: to write to log file
        		System.out.println("\nTVSTable: GRI is present in the table and its context will be replaced");
        	}        	
        }
        if (!griToReplace.equals("")) {
        	domainSessions.remove(griToReplace);
        }
        domainSessions.put(gri, sessionCtx);
        ///
        domainsT.remove(domainToReplace);
        domainsT.put(domainToReplace, domainSessions);
        
        storeTVSTableInExist(domainsT);
        
    	return true;
	}
	
}

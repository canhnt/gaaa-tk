/* 
 * Copyright (c) 2007, Fraunhofer-Gesellschaft
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 * (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the disclaimer at the end.
 *     Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 * 
 * (2) Neither the name of Fraunhofer nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 * 
 * DISCLAIMER
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 */
package org.aaaarch.gaaapi.test.unicore6;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Vector;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.dom.DOMSource;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.soap.SOAPFactory;
import org.apache.axis2.context.MessageContext;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.CryptoBase;
import org.apache.xmlbeans.XmlOptions;
import org.ogf.graap.wsag.api.engine.WsagEngine;
import org.ogf.graap.wsag.api.engine.WsagMessageContext;
import org.ogf.graap.wsag.security.core.SecurityConstants;

import pl.edu.icm.unicore.security.UnicoreSecurityFactory;
import pl.edu.icm.unicore.security.ValidationResult;
import pl.edu.icm.unicore.security.etd.DelegationRestrictions;
import pl.edu.icm.unicore.security.etd.ETDApi;
import pl.edu.icm.unicore.security.etd.TrustDelegation;

import junit.framework.TestCase;

import org.w3c.dom.Node;



/**
 * TestTrustDelegation 
 *
 * @author Oliver Wäldrich
 *
 */
public class TestTrustDelegation extends TestCase {

    /*
    private static final String PASSWORD1 = "user@wsag4j";
    private static final String PASSWORD2 = "server@wsag4j";
    private static final String ALIAS1 = "wsag4j-user";
    private static final String ALIAS2 = "wsag4j-server";
    
    private static final String KEYSTORE1 = "wsag4j-client-keystore.jks";
    private static final String KEYSTORE2 = "wsag4j-server-keystore.jks";
    
    
    private KeyStore ks1, ks2;
    protected X509Certificate[] issuerCert1, receiverCert1;
    protected X509Certificate[] issuerCert2, receiverCert2;
    protected String issuerDN1, issuerDN2;
    protected String receiverDN1, receiverDN2;
    protected PrivateKey privKey1, privKey2, privKey3;
    */
    
    private static final String PASSWORD = "dummy-pwd";
    private static final String ALIAS = "alias";
    
    private static final String KEYSTORE1 = "keystoreRSA1.jks";
    private static final String KEYSTORE2 = "keystoreRSA2.jks";
    private static final String KEYSTORE3 = "keystoreDSA1.jks";
    private static final String KEYSTORE4 = "keystoreDSA2.jks";
    
    
    private KeyStore ks1, ks2, ks3, ks4;
    protected X509Certificate[] issuerCert1, receiverCert1;
    protected X509Certificate[] issuerCert2, receiverCert2;
    protected String issuerDN1, issuerDN2;
    protected String receiverDN1, receiverDN2;
    protected PrivateKey privKey1, privKey2, privKey3;
    protected XmlOptions xmlOpts;
    
    protected ETDApi etdEngine;    

    public void testTrustDelegation() throws Exception {
        TrustDelegation td = etdEngine.generateTD(issuerCert1[0].getSubjectX500Principal().getName(), 
                                                  issuerCert1,
                                                  privKey1, 
                                                  receiverCert1[0].getSubjectX500Principal().getName(), 
                                                  null);
        
        ValidationResult result = etdEngine.validateTD(td, 
                                                       issuerCert1[0].getSubjectX500Principal().getName(), 
                                                       issuerCert1[0].getSubjectX500Principal().getName(), 
                                                       receiverCert1[0].getSubjectX500Principal().getName());
        System.out.println(result.getInvalidResaon());
        assertTrue(result.isValid());

        SOAPEnvelope env = generateEnvelope(new TrustDelegation[] {td} );
        
        initializeWSAG4JContext(issuerCert1, receiverCert1);
        
        MessageContext.setCurrentMessageContext(new MessageContext());
        MessageContext.getCurrentMessageContext().setEnvelope(env);
        
        Unicore6ServerSecurityHandler handler = new Unicore6ServerSecurityHandler();
        handler.handleRequest(env);
        
        Object validatedTD = WsagMessageContext.getCurrentMessageContext().get(SecurityConstants.SAML_TRUST_DELEGATION);

        assertNotNull(validatedTD);
        assertTrue(validatedTD instanceof List);
        assertEquals(1, ((List)validatedTD).size());
    }

    public void testTrustDelegationChain() throws Exception {
        DelegationRestrictions restrictions = new DelegationRestrictions(new Date(), 1, 3);

        TrustDelegation td1 = 
                      etdEngine.generateTD( issuerCert1[0].getSubjectX500Principal().getName(), 
                                            issuerCert1,
                                            privKey1, 
                                            receiverCert1[0].getSubjectX500Principal().getName(), 
                                            restrictions);
        
        ValidationResult result = etdEngine.validateTD( td1, 
                                                        issuerCert1[0].getSubjectX500Principal().getName(), 
                                                        issuerCert1[0].getSubjectX500Principal().getName(), 
                                                        receiverCert1[0].getSubjectX500Principal().getName());

        System.out.println(result.getInvalidResaon());
        assertTrue(result.isValid());
        
        List tdList = new Vector();
        tdList.add(td1);

        tdList = etdEngine.issueChainedTD( tdList, 
                                           receiverCert1, 
                                           privKey3, 
                                           receiverCert2[0].getSubjectX500Principal().getName(), 
                                           restrictions);

        TrustDelegation[] tdArray = (TrustDelegation[])tdList.toArray(new TrustDelegation[tdList.size()]);
        SOAPEnvelope env = generateEnvelope(tdArray);
        
        initializeWSAG4JContext(receiverCert1, receiverCert2);
        
        MessageContext.setCurrentMessageContext(new MessageContext());
        MessageContext.getCurrentMessageContext().setEnvelope(env);
        
        Unicore6ServerSecurityHandler handler = new Unicore6ServerSecurityHandler();
        handler.handleRequest(env);
        
        Object validatedTD = WsagMessageContext.getCurrentMessageContext().get(SecurityConstants.SAML_TRUST_DELEGATION);

        assertNotNull(validatedTD);
        assertTrue(validatedTD instanceof List);
        assertEquals(2, ((List)validatedTD).size());
    }

    private void initializeWSAG4JContext(X509Certificate[] issuer, final X509Certificate[] receiver) {
        WsagMessageContext context = WsagEngine.getWsagMessageContext();
        
        CryptoBase crypto = new CryptoBase() {

            protected String getCryptoProvider() {
                return null;
            }

            public String getDefaultX509Alias() {
                return "default-alias";
            }
            
            public X509Certificate[] getCertificates(String alias) throws WSSecurityException {
                if (alias.equals("default-alias")) {
                    return receiver;
                }
                return null;
            }
            
        };
        
        crypto.setKeyStore(ks1);
        context.put(SecurityConstants.WSAG4J_SERVER_CRYPTO, crypto);
        context.put(SecurityConstants.X509_CLIENT_CERTIFICATE, issuer[0]);
        context.put(SecurityConstants.X509_CLIENT_CERTIFICATE_CHAIN, issuer);
    }
    
    private SOAPEnvelope generateEnvelope(TrustDelegation[] tdc) throws Exception {
        //create a factory
        SOAPFactory factory = OMAbstractFactory.getSOAP12Factory();
        SOAPEnvelope env = factory.createSOAPEnvelope();
        env.addChild(factory.createSOAPHeader());

        for (int i = 0; i < tdc.length; i++) {
            Node xml = tdc[i].getXML().getDomNode();
             
            XMLStreamReader parser = XMLInputFactory.newInstance().createXMLStreamReader(new DOMSource(xml));
            StAXOMBuilder builder = new StAXOMBuilder(parser);
            OMElement documentElement =  builder.getDocumentElement();      
            
            env.getHeader().addChild(documentElement);
        }
        
        return env;
    }
    
    /*
    protected void setUp() {
        try {
            
            ks1 = KeyStore.getInstance("JKS");
            InputStream is = getClass().getResourceAsStream("/" + KEYSTORE1);
            ks1.load(is, PASSWORD1.toCharArray());
            
            ks2 = KeyStore.getInstance("JKS");
            is = getClass().getResourceAsStream("/" + KEYSTORE2);
            ks2.load(is, PASSWORD2.toCharArray());

            issuerCert1 = convertChain(ks1.getCertificateChain(ALIAS1));
            receiverCert1 = convertChain(ks2.getCertificateChain(ALIAS2));
            
            issuerCert2 = receiverCert1;
            receiverCert2 = issuerCert1;
            
            privKey1 = (PrivateKey) ks1.getKey(ALIAS1, PASSWORD1.toCharArray());
            privKey2 = (PrivateKey) ks2.getKey(ALIAS2, PASSWORD2.toCharArray());
            
            issuerDN1 = issuerCert1[0].getSubjectX500Principal().getName();
            receiverDN1 = receiverCert1[0].getSubjectX500Principal().getName();

            etdEngine = UnicoreSecurityFactory.getETDEngine();
            
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
*/
    
    protected void setUp() {
        try {
            ks1 = KeyStore.getInstance("JKS");
            InputStream is = getClass().getResourceAsStream("/" + KEYSTORE1);
            ks1.load(is, PASSWORD.toCharArray());
            
            ks2 = KeyStore.getInstance("JKS");
            is = getClass().getResourceAsStream("/" + KEYSTORE2);
            ks2.load(is, PASSWORD.toCharArray());

            ks3 = KeyStore.getInstance("JKS");
            is = getClass().getResourceAsStream("/" + KEYSTORE3);
            ks3.load(is, PASSWORD.toCharArray());
            
            ks4 = KeyStore.getInstance("JKS");
            is = getClass().getResourceAsStream("/" + KEYSTORE4);
            ks4.load(is, PASSWORD.toCharArray());
            
            issuerCert1 = convertChain(ks1.getCertificateChain(ALIAS));
            receiverCert1 = convertChain(ks2.getCertificateChain(ALIAS));
            issuerCert2 = convertChain(ks3.getCertificateChain(ALIAS));
            receiverCert2 = convertChain(ks4.getCertificateChain(ALIAS));
            
            privKey1 = (PrivateKey) ks1.getKey(ALIAS, PASSWORD.toCharArray());
            privKey2 = (PrivateKey) ks3.getKey(ALIAS, PASSWORD.toCharArray());
            privKey3 = (PrivateKey) ks2.getKey(ALIAS, PASSWORD.toCharArray());
            
            issuerDN1 = issuerCert1[0].getSubjectX500Principal().getName();
            receiverDN1 = receiverCert1[0].getSubjectX500Principal().getName();
            issuerDN2 = issuerCert2[0].getSubjectX500Principal().getName();
            receiverDN2 = receiverCert2[0].getSubjectX500Principal().getName();

            etdEngine = UnicoreSecurityFactory.getETDEngine();
            
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
    
    private X509Certificate[] convertChain(Certificate[] chain) {
        
        X509Certificate[] ret = new X509Certificate[chain.length];
        for (int i=0; i<chain.length; i++)
            ret[i] = (X509Certificate) chain[i];
        return ret;
        
    }
}

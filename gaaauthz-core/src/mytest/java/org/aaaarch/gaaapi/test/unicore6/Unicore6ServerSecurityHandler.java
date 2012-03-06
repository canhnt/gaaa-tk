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

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamReader;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.soap.SOAPHeader;
import org.apache.axis2.context.MessageContext;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.xmlbeans.XmlException;
import org.ogf.graap.wsag.api.engine.WsagMessageContext;
import org.ogf.graap.wsag.security.core.SecurityConstants;
import org.ogf.graap.wsag.security.core.server.ServerSecurityHandler;
import org.w3c.dom.Element;

import de.fraunhofer.scai.mss.common.logging.MSSLogger;

import pl.edu.icm.unicore.saml.SAMLParseException;
import pl.edu.icm.unicore.security.UnicoreSecurityFactory;
import pl.edu.icm.unicore.security.ValidationResult;
import pl.edu.icm.unicore.security.etd.ETDApi;
import pl.edu.icm.unicore.security.etd.TrustDelegation;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;

/**
 * Unicore6ServerSecurityHandler 
 *
 * @author Oliver Wäldrich
 *
 */
public class Unicore6ServerSecurityHandler implements ServerSecurityHandler {

    private ETDApi etd;
    private boolean useTDReceiverCertificates = false;
    private boolean lastHopValidation = true;
    
    public Unicore6ServerSecurityHandler() {
        etd = UnicoreSecurityFactory.getETDEngine();
    }
    
    /* (non-Javadoc)
     * @see org.ogf.graap.wsag.server.handler.MessageHandler#handleRequest(org.apache.axiom.om.OMElement)
     */
    public void handleRequest(OMElement request) throws Exception {
        MessageContext messageContext = MessageContext.getCurrentMessageContext();

        WsagMessageContext context = WsagMessageContext.getCurrentMessageContext();
        context.remove(SecurityConstants.SAML_TRUST_DELEGATION);
        
        Crypto crypto = (Crypto) context.get(SecurityConstants.WSAG4J_SERVER_CRYPTO);
        if (crypto == null) {
            String error = "No server crypto found in the wsag4j message context.";

            MSSLogger.error(error);
            throw new WSSecurityException(error);
        }

        X509Certificate userCertificate = (X509Certificate) context.get(SecurityConstants.X509_CLIENT_CERTIFICATE);
        if (userCertificate == null) {
            String error = "No client certificate found in the wsag4j message context. (hint: is the ws-security message handler configured correctly?)";

            MSSLogger.error(error);
            throw new WSSecurityException(error);
        }
        
        X509Certificate[] userCertificateChain = (X509Certificate[]) context.get(SecurityConstants.X509_CLIENT_CERTIFICATE_CHAIN);
        if (userCertificateChain == null) {
            String error = "No client certificate chain found in the wsag4j message context. (hint: is the ws-security message handler configured correctly?)";

            MSSLogger.error(error);
            throw new WSSecurityException(error);
        }
        
        SOAPEnvelope envelope  = messageContext.getEnvelope();
        SOAPHeader header      = envelope.getHeader();
        
        // Here is SAML assertion extracted from header
        Iterator assertions = header.getChildrenWithName(new QName("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion"));
        
        List trustDelegations = new Vector();
        
        while (assertions.hasNext()) {
            
            try {
                OMElement assertion = (OMElement) assertions.next(); 
                XMLStreamReader assertionReader = assertion.getXMLStreamReaderWithoutCaching();
                AssertionDocument assertionDocument = AssertionDocument.Factory.parse(assertionReader);
                trustDelegations.add(new TrustDelegation(assertionDocument));
            } 
            catch (XmlException e) {
                throw new SecurityException(e);
            } 
            catch (IOException e) {
                throw new SecurityException(e);
            } 
            catch (SAMLParseException e) {
                throw new SecurityException(e);
            }
            
        }
        
        if (trustDelegations.size() == 1) {
            TrustDelegation trustDelegation = (TrustDelegation) trustDelegations.get(0);
            checkTrustDelegation(context, crypto, trustDelegation, userCertificate, userCertificateChain);
        }
        else if (trustDelegations.size() > 1) {
            checkChainedTrustDelegation(context, crypto, trustDelegations, userCertificateChain);
        }
    }

    /* (non-Javadoc)
     * @see org.ogf.graap.wsag.server.handler.MessageHandler#handleResponse(org.w3c.dom.Element)
     */
    public void handleResponse(Element response) throws Exception {
        // nothing to do
    }


    private void checkTrustDelegation(WsagMessageContext context, Crypto crypto, TrustDelegation trustDelegation, X509Certificate issuerCertificate, X509Certificate[] issuerCertificateChain) {
        MSSLogger.info("AxisHandler: Found trust delegation SAML assertion in request.");

        try {
            X509Certificate[] receiver = crypto.getCertificates(crypto.getDefaultX509Alias());

            ValidationResult validate = validateTDToken(trustDelegation, 
                                                        issuerCertificate, 
                                                        issuerCertificateChain, 
                                                        receiver);
            
            List tdChain = new Vector();
            
            if (validate.isValid()) {
                tdChain.add(trustDelegation);
                context.put(SecurityConstants.SAML_TRUST_DELEGATION, tdChain);

                MSSLogger.info("AxisHandler: Validation of SAML trust delegation successful.");
            }
            else {
                String message = "AxisHandler: Validation of SAML trust delegation faild. Reason: $1";
                MSSLogger.error(message, validate.getInvalidResaon());
            }
        } catch (IOException e) {
            throw new SecurityException(e);
        }
    }

    private void checkChainedTrustDelegation(WsagMessageContext context, Crypto crypto, List trustDelegations, X509Certificate[] senderCertificateChain) {
        MSSLogger.info("AxisHandler: Found trust delegation SAML assertion in request.");

        try {
            X509Certificate[] receiver = crypto.getCertificates(crypto.getDefaultX509Alias());
            TrustDelegation initial = (TrustDelegation)trustDelegations.get(0);
            X509Certificate[] issuerCerts = initial.getIssuerFromSignature();
            
            ValidationResult validate;

            if (lastHopValidation) {
                //
                // Validation of the last hop. We need to validate whether trust
                // was delegated to the sender of the message. The certificate of 
                // the message sender we retrieved from the message signature.
                //
                List lastHop = new Vector();
                lastHop.addAll(trustDelegations);
                lastHop.remove(lastHop.size()-1);
                
                if (lastHop.size() == 1) {
                    TrustDelegation trustDelegation = (TrustDelegation) lastHop.get(0);
                    validate = validateTDToken(trustDelegation, issuerCerts[0], issuerCerts, senderCertificateChain);
                }
                else {
                    validate = validateTDChain(lastHop, senderCertificateChain, receiver);
                }
                
                if (!validate.isValid()) {
                    String message = "AxisHandler: Validation of SAML chained trust delegation faild. \n" +
                    		         "Trust was not delegated to sender of the message.\n" +
                    		         "Reason: $1";
                    MSSLogger.error(message, validate.getInvalidResaon());
                }
            }
            
            //
            // Validation of the full trust delegation chain
            //
            validate = validateTDChain( trustDelegations, 
                                        issuerCerts, 
                                        receiver);
            
            
            if (validate.isValid()) {
                context.put(SecurityConstants.SAML_TRUST_DELEGATION, trustDelegations);
                MSSLogger.info("AxisHandler: Validation of SAML chained trust delegation successful.");
            }
            else {
                String message = "AxisHandler: Validation of SAML chained trust delegation faild. Reason: $1";
                MSSLogger.error(message, validate.getInvalidResaon());
            }
        } 
        catch (IOException e) {
            throw new SecurityException(e);
        }
    }
    
    private ValidationResult validateTDToken(TrustDelegation trustDelegation, 
                                             X509Certificate issuerCertificate, 
                                             X509Certificate[] issuerCertificateChain, 
                                             X509Certificate[] receiver) {
        
        if (useTDReceiverCertificates) {
            return etd.validateTD( trustDelegation, 
                                   issuerCertificate, 
                                   issuerCertificateChain, 
                                   receiver);
        }
        else {
            return etd.validateTD( trustDelegation, 
                                   issuerCertificate.getSubjectX500Principal().getName(), 
                                   issuerCertificateChain[0].getSubjectX500Principal().getName(), 
                                   receiver[0].getSubjectX500Principal().getName()
                                  );
        }
    }

    private ValidationResult validateTDChain(List trustDelegations, 
                                             X509Certificate[] issuerCertificateChain, 
                                             X509Certificate[] receiver) {

        if (useTDReceiverCertificates) {
            return etd.isTrustDelegated( trustDelegations, 
                                         receiver, 
                                         issuerCertificateChain);        
        }
        else {
            return etd.isTrustDelegated( trustDelegations, 
                                         receiver[0].getSubjectX500Principal().getName(), 
                                         issuerCertificateChain[0].getSubjectX500Principal().getName());        
        }
    }

    /**
     * @return the useTDReceiverCertificates
     */
    public boolean isUseTDReceiverCertificates() {
        return useTDReceiverCertificates;
    }

    /**
     * @param useTDReceiverCertificates the useTDReceiverCertificates to set
     */
    public void setUseTDReceiverCertificates(boolean useTDReceiverCertificates) {
        this.useTDReceiverCertificates = useTDReceiverCertificates;
    }
}

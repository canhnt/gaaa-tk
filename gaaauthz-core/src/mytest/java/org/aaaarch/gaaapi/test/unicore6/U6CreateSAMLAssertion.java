/*
 * Template provided by Björn Hagemeier
 * localisation and bootstrapping done by Y.Demchenko
 * 
 */

package org.aaaarch.gaaapi.test.unicore6;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import junit.framework.TestCase;

import org.apache.xmlbeans.XmlException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pl.edu.icm.unicore.saml.SAMLParseException;
import pl.edu.icm.unicore.security.UnicoreSecurityFactory;
import pl.edu.icm.unicore.security.dsig.DSigException;
import pl.edu.icm.unicore.security.etd.DelegationRestrictions;
import pl.edu.icm.unicore.security.etd.ETDApi;
import pl.edu.icm.unicore.security.etd.TrustDelegation;
import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import de.fzj.hila.implementation.unicore6.Unicore6SecurityProperties;

public class U6CreateSAMLAssertion extends TestCase
{

  private static final Logger log = LoggerFactory.getLogger(U6CreateSAMLAssertion.class);

  public void testCreate() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException, DSigException, SAMLParseException, XmlException
  {
    String clientAlias = "proawar0";
    String clientJKSPath = "/home/bjoernh/.hila/proawar0.jks";
    char[] clientJKSPass = "proawar0".toCharArray();

    String serverAlias = "server";
    String serverJKSPath = "/home/bjoernh/Daten/JSC/Development/saml-creator/server.jks";
    char[] serverJKSPass = "alibaba".toCharArray();

    KeyStore clientJKS = KeyStore.getInstance(KeyStore.getDefaultType());
    clientJKS.load(new FileInputStream(new File(clientJKSPath)), clientJKSPass);

    String issuerDN = "null";
    X509Certificate clientX509 = null;

    Certificate clientCert = clientJKS.getCertificate(clientAlias);
    if (clientCert instanceof X509Certificate)
    {
      clientX509 = (X509Certificate) clientCert;
      issuerDN = clientX509.getSubjectDN().getName();
      log.info("Issuer DN: " + issuerDN);
    }

    KeyStore serverJKS = KeyStore.getInstance(KeyStore.getDefaultType());
    serverJKS.load(new FileInputStream(new File(serverJKSPath)), serverJKSPass);
    Certificate serverCert = serverJKS.getCertificate(serverAlias);
    log.info("Server cert: " + serverCert);
    String serverDN = "null";
    if(serverCert instanceof X509Certificate)
    {
      X509Certificate serverX509 = (X509Certificate) serverCert;
      serverDN = serverX509.getSubjectDN().getName();
      log.info("Server DN: " + serverDN);
    }
    
    ETDApi engine = UnicoreSecurityFactory.getETDEngine();
    Calendar until = Calendar.getInstance();
    until.add(Calendar.DATE, 1);
    DelegationRestrictions dr = new DelegationRestrictions(Calendar.getInstance().getTime(), until.getTime(), 10);
    TrustDelegation td = engine.generateTD(issuerDN, new X509Certificate[]{clientX509}, (PrivateKey)clientJKS.getKey(clientAlias, clientJKSPass), serverDN, dr);
    
    //log.info(td.getXML().toString());
    
    // Security properties
    
    Unicore6SecurityProperties u6sp = new Unicore6SecurityProperties("/home/bjoernh/.hila/cineca.security");
    List<TrustDelegation> tdList = u6sp.getTrustDelegationTokens();
    if(tdList == null) {
      tdList = new ArrayList<TrustDelegation>();
    }
    
    // Here SAML Assertion is created
    tdList.add(new TrustDelegation(AssertionDocument.Factory.parse(td.getXML().toString())));
    for (TrustDelegation trustDelegation : tdList)
    {
      log.info(trustDelegation.getXML().toString());
    }
    u6sp.setTrustDelegationTokens(tdList);
    log.info(u6sp.toString());
  }
}

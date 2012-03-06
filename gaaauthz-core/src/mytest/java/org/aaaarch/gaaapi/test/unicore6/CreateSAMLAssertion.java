package org.aaaarch.gaaapi.test.unicore6;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;

import junit.framework.TestCase;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.unicore.security.UnicoreSecurityFactory;
import eu.unicore.security.etd.DelegationRestrictions;
import eu.unicore.security.etd.ETDApi;
import eu.unicore.security.etd.TrustDelegation;

public class CreateSAMLAssertion extends TestCase
{

  private static final Logger log = LoggerFactory.getLogger(CreateSAMLAssertion.class);

  public void testCreate() throws Exception
  {
    String issuerAlias = "mykey";
    String issuerJKSPath = "etc/security/keystore/unicore6/store1.jks";
    char[] issuerJKSPass = "asdfasdf".toCharArray();

    String subjectAlias = "mykey";
    String subjectJKSPath = "etc/security/keystore/unicore6/store2.jks";
    char[] subjectJKSPass = "asdfasdf".toCharArray();

    KeyStore issuerJKS = KeyStore.getInstance(KeyStore.getDefaultType());
    issuerJKS.load(new FileInputStream(new File(issuerJKSPath)), issuerJKSPass);

    String issuerDN = "null";
    X509Certificate issuerX509 = null;

    Certificate issuerCert = issuerJKS.getCertificate(issuerAlias);
    if (issuerCert instanceof X509Certificate)
    {
      issuerX509 = (X509Certificate) issuerCert;
      issuerDN = issuerX509.getSubjectDN().getName();
      log.info("Issuer DN: " + issuerDN);
    }

    KeyStore subjectJKS = KeyStore.getInstance(KeyStore.getDefaultType());
    subjectJKS.load(new FileInputStream(new File(subjectJKSPath)), subjectJKSPass);
    Certificate serverCert = subjectJKS.getCertificate(subjectAlias);
    log.info("Server cert: " + serverCert);
    String subjectDN = "null";
    if (serverCert instanceof X509Certificate)
    {
      X509Certificate serverX509 = (X509Certificate) serverCert;
      subjectDN = serverX509.getSubjectDN().getName();
      log.info("Server DN: " + subjectDN);
    }

    ETDApi engine = UnicoreSecurityFactory.getETDEngine();
    Calendar until = Calendar.getInstance();
    until.add(Calendar.MONTH, 1);
    DelegationRestrictions dr = new DelegationRestrictions(Calendar.getInstance().getTime(), until.getTime(), 10);
    TrustDelegation td = engine.generateTD(issuerDN, new X509Certificate[]
    { issuerX509}, (PrivateKey) issuerJKS.getKey(issuerAlias, issuerJKSPass), subjectDN, dr);

    log.info(td.getXML().toString());
    
    System.out.println("Assertion is created");
  }
}

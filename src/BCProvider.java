/**
 * Created by cgorlt on 10/23/2016.
 */


import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.provider.X509CRLObject;
import org.bouncycastle.jce.provider.X509CertificateObject;
import sun.applet.Main;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRLEntry;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

//import java.util.HashMap;


public class BCProvider {


    private boolean debug;
    private X509CertificateObject certificate;

    private static final String SUBJECT_KEY_IDENTIFIER   = "2.5.29.14";
    private static final String AUTHORITY_KEY_IDENTIFIER = "2.5.29.35";
    private static final String BASIC_CONSTRAINTS_IDENTIFIER = "2.5.29.19";
    private static final String KEY_USAGE_IDENTIFIER = "2.5.29.15";
    private static final String PRIVATE_KEY_USAGE_PERIOD_IDENTIFIER = "2.5.29.16";
    private static final String NAME_CONSTRAINTS_IDENTIFIER = "2.5.29.30";
    private static final String CERTIFICATES_POLICIES_IDENTIFIER = "2.5.29.32";
    private static final String POLICY_CONSTRAINTS_IDENTIFIER = "2.5.29.36";
    private static final String SUBJECT_ALTERNATIVE_NAME_IDENTIFIER = "2.5.29.17";
    private static final String ISSUER_ALTERNATIVE_NAME_IDENTIFIER = "2.5.29.18";
    private static final String SUBJECT_DIRECTORY_ATTRIBUTES_IDENTIFIER = "2.5.29.9";
    private static final String EXTENDED_KEY_USAGE_IDENTIFIER = "2.5.29.37";
    private static final String CRL_DISTRIBUTION_POINT_IDENTIFIER = "2.5.29.31";
    private static final String INHIBIT_ANY_POLICY_IDENTIFIER = "2.5.29.54";
    private static final String FRESHESTCRL_IDENTIFIER = "2.5.29.46";
    private static final String NETSCAPE_CERT_EXTENSIONS_IDENTIFIER = "2.16.840.1.113730.1.1";
    private static final String PRIVATE_NTERNET_EXTENSION_IDENTIFIER = "1.3.6.1.5.5.7.48";
    private static final String DOCUMENT_TYPE_IDENTIFIER = "2.23.136.1.1.6.2";
    private static final String CRL_NUMBER_IDENTIFIER = "2.5.29.20";
    private static final String CRL_DELTA_INDICATOR_IDENTIFIER = "2.5.29.27";
    private static final String CRL_ISSUING_DISTRIBUTION_POINT_IDENTIFIER = "2.5.29.28";
    private static final String CRL_ENTRY_REASON_CODE_IDENTIFIER = "2.5.29.21";
    private static final String CRL_ENTRY_HOLD_INSTRUCTION_CODE_IDENTIFIER = "2.5.29.23";
    private static final String CRL_ENTRY_INVALIDITY_DATE_IDENTIFIER = "2.5.29.24";
    private static final String CRL_ENTRY_CERTIFICATE_ISSUER_IDENTIFIER = "2.5.29.29";

    File logFile = new File("C:\\Windows\\Temp\\Chirimayo.log");
    //merci http://stackoverflow.com/questions/1379434/how-to-get-the-hash-algorithm-name-using-the-oid-in-java
    private static final Map<String,String> algorithms = new HashMap<String,String>();

    /**
     KeyUsage ::= BIT STRING {
     digitalSignature        (0),
     nonRepudiation          (1),
     keyEncipherment         (2),
     dataEncipherment        (3),
     keyAgreement            (4),
     keyCertSign             (5),
     cRLSign                 (6),
     encipherOnly            (7),
     decipherOnly            (8) }
     */
    public static String[] keyUsage = {"digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment", "keyAgreement", "keyCertSign", "crlSign", "encipherOnly", "decipheronly"};


    public BCProvider(X509CertificateObject cert, boolean bool) throws IOException{
        this.certificate = cert;
        this.debug = bool;
    }
    public BCProvider()throws IOException{
        this.certificate = null;
        this.debug = true;
    }
    public BCProvider(boolean bool)throws IOException{
        this.certificate=null;
        this.debug=bool;
    }







    //***************************VERSION
    /*
     * CSCA certificate should have be version 3
     * ERR:CSCA.VER.12
     */
    final Boolean verifCSCAisVersion3(X509CertificateObject cert){
        if (debug){MainFrame.logger("....starting verifCSCAisVersion3");}
        if (cert.getVersion() == 3) {
            return Boolean.TRUE;
        }else { return Boolean.FALSE;}
    }

    //***********************************SERIAL NUMBER
    /*
     *CSCA certificate should have a serial number
     * ERR:CSCA.SER.14
     */
    final Boolean verifCSCASerialisPresent (X509CertificateObject cert){
        if (debug){MainFrame.logger("....starting verifCSCAPresenceSerialNumber");}
        try {
            if (cert.getSerialNumber() != null) {
                return Boolean.TRUE;
            }else{return Boolean.FALSE;}
        }catch (Exception e){
            return Boolean.FALSE;
        }
    }

    /*
     *CSCA certificate should have a non-negative serial number
     *ERR:CSCA.SER.0
     */
    final Boolean verifCSCASerialisNotNegative(X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCASerialisNotNegative");}
        if (cert.getSerialNumber().signum() == 1){ // signum returns 1 if bigger than zero
            return Boolean.TRUE;
        }else{ return Boolean.FALSE;}
    }

    /*
     *CSCA certificate may be zero, but then warning should be sent
     *WARN:CSCA.SER.0
     */
    final Boolean verifCSCASerialisNotZero (X509CertificateObject cert){
        if (debug){MainFrame.logger("....starting verifCSCASerialisNotZero");}
        if (cert.getSerialNumber().intValue() != 0) {
            return Boolean.TRUE;
        }else {return Boolean.FALSE;}
    }

    //TODO Is not 2’s complement encoding                        ERR:CSCA.SER.1
    //TODO Not smallest number of octets representation          ERR:CSCA.SER.2

    /*
     *CSCA certificate should NOT have a serial number greater than 20 Octets -> to be verified
     * ERR:CSCA.SER.3
     */
    final Boolean verifCSCASerialNumberisNotLongerThan20Bytes (X509CertificateObject cert){
        if (debug){MainFrame.logger("....starting verifCSCASerialNumberisNotLongerThan20Byte");}
        if (debug){MainFrame.logger("    bit count was: " + cert.getSerialNumber().bitCount() + "->" + (cert.getSerialNumber().bitCount() / 8) + "bytes");}
        int byteNumber=cert.getSerialNumber().bitCount()/8;
        if (byteNumber % 8 != 0){
            byteNumber++;
        }
        if (byteNumber < 20) {
            return Boolean.TRUE;
        }else {
            return Boolean.FALSE;
        }
    }

    //******************************SIGNATURE ALGORITHM
    /*
     *CSCA certificate should use SHA-224, SHA-256, SHA-384 or SHA-512 as signing algorihtm
     * ERR:CSCA.SIG.42-43
     */
    final Boolean verifCSCASigningAlgorithm (X509CertificateObject cert) {
        if (debug) {
            MainFrame.logger("....starting verifCSCASigningAlgorithm");
        }
        fillupOidAlgoNameMap();
        String regex = "^([0-9\\.]*)$"; // regex tested again german CSCA
        Pattern r = Pattern.compile(regex);
        Matcher m = r.matcher(cert.getSigAlgName());
        String algo=null;
        if (m.find()) {
            if (debug){MainFrame.logger("    signing algo was matching the regex for OID:" + cert.getSigAlgName());}
            String oid = m.group(1);
            try {
                String mappingResult=getKeysByValue(algorithms,oid);
                if (mappingResult != null){
                    algo=mappingResult;
                    if (debug){MainFrame.logger("    conversion to algName result succedded: " + algo);}
                }else{
                    if (debug) {MainFrame.logger("    the conversion to alg name returned null-> not ok");}
                    return Boolean.FALSE;//return false because we could find out what algorythm this OID was
                }

            }catch(Exception e){
                MainFrame.logger("exception:" + e.getMessage());
                if (debug){MainFrame.logger("    could not complete oId-algorithmName  conversion, oId was:" + oid);}
                //maybe add return false car ca veut dire qu'on a pas su parser en SHA 256, 512 ou les autres autorisé ?.
            }
            //return Boolean.TRUE; // for the moment this is not done, don't raise a point if it is not sure -->//TO DO ASAP
        }else {
            if (debug) {MainFrame.logger("    the algorithm is already given as a string, not an oId");}
            algo=cert.getSigAlgName();
        }
        if (algo.contains("SHA224") || algo.contains("SHA256") || algo.contains("SHA384") || algo.contains("SHA512")) {
            if (debug){MainFrame.logger("    the algo name match with SHA224||256||384||512");}
            return Boolean.TRUE;
        } else {
            if (debug) {
                MainFrame.logger("    verification failed-> Sig Algo name was: " + cert.getSigAlgName());
            }
            return Boolean.FALSE;
        }
    }

    //************************************ISSUER
    /*
     *CSCA LINK certificate should have a Issuer  field
     * ERR:CSCA.ISS.14
     */
    final Boolean verifCSCALinkIssuerisPresent (X509CertificateObject cert){
        if (debug){MainFrame.logger("....starting verifCSCALinkIssuerisPresent");}
        try {
            if (cert.getIssuerX500Principal().getName() == "" ||cert.getIssuerX500Principal().getName() == null) {
                if (debug){MainFrame.logger("    Issuer was empty or null");}
                return Boolean.FALSE;
            }else {
                if (debug){MainFrame.logger("    Issuer was ok:" + cert.getIssuerX500Principal().getName());}
                return Boolean.TRUE;
            }
        }catch (Exception e) {
            if (debug){MainFrame.logger("    parsing Issuer field failed");}
            return Boolean.FALSE;
        }
    }

    /*
     *CSCA LINK certificate should have country code field in the Issuer
     * ERR:CSCA.ISS.10
     */
    final Boolean verifCSCALinkCountryCodeInIssuerisPresent (X509CertificateObject cert){
        if (debug){MainFrame.logger("....starting verifCSCALinkCountryCodeInIssuerisPresent");}
        String regex = "(.*)C\\=([^,]*)(.*)";
        Pattern r = Pattern.compile(regex);
        Matcher m = r.matcher(cert.getIssuerX500Principal().getName());
        if (m.find()) {
            if (debug){MainFrame.logger("    C field found:" + m.group(2));}
            if (m.group(2).length() == 2) {return Boolean.TRUE;}
            else {
                if (debug){MainFrame.logger("    C field found, but should be two letter code. was:|" + m.group(2) + "|");}
                return Boolean.FALSE;
            }
        }else {
            if (debug){MainFrame.logger("    no C field found, Issuer was:" + cert.getIssuerX500Principal().getName());}
            return Boolean.FALSE;
        }
    }

    /*
     *CSCA certificate should have the issuer common name field
     * WARN:CSCA.ISS.34 ERR:CSCA.ISS.34
     */
    final Boolean verifCSCACommonNameInIssuerisPresent (X509CertificateObject cert){
        if (debug){MainFrame.logger("....starting verifCSCACommonNameInIssuerisPresent");}
        String regex = "(.*)CN\\=([^,]*)(.*)";
        Pattern r = Pattern.compile(regex);
        Matcher m = r.matcher(cert.getIssuerX500Principal().getName());
        if (m.find()) {
            if (debug){MainFrame.logger("    CN field found:" + m.group(2));}
            return Boolean.TRUE;
        }else {
            if (debug){MainFrame.logger("    no CN field found, issuer was:" + cert.getIssuerX500Principal().getName());}
            return Boolean.FALSE;
        }
    }

    //TODO String encoding other than UTF8 or PrintableString ERR:CSCA.ISS.11 (CSCA LINK)

    //**********************************VALIDITY
    /*
     *CSCA certificate should have a validity field (field should be present)
     * ERR:CSCA.VAL.14
     */
    final Boolean verifCSCAValidityisPresent (X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCAValidityisPresent");}
        try {
            Date earliest = cert.getNotBefore();
            Date latest = cert.getNotAfter();
            if ( earliest == null || latest == null) {
                if (debug){MainFrame.logger("    either NotBefore or NotAfter field were empty or null");}
                return Boolean.FALSE;
            }else{return Boolean.TRUE;}
        }catch (Exception e) {
            if (debug){MainFrame.logger("    parsing NotBefore and NotAfter field failed");}
            return Boolean.FALSE;
        }
    }

    //TODO Date less the 2050 encoded as GeneralizedTime     ERR:CSCA.VAL.4
    //TODO Date greater than 2049 encoded as UTCTime        ERR:CSCA.VAL.5
    //TODO Generalized Time has fractional seconds          ERR:CSCA.VAL.6
    //TODO UTCTime encoding is wrong                         ERR:CSCA.VAL.7
    //TODO Generalized Time encoding is wrong                ERR:CSCA.VAL.8

    //******************************************SUBJECT
    /*
     *CSCA certificate should have a subject field
     * ERR:CSCA.SUB.14
     */
    final Boolean verifCSCASubjectisPresent (X509CertificateObject cert){
        if (debug){MainFrame.logger("....starting verifCSCASubjectisPresent");}
        try {
            if (cert.getSubjectX500Principal().getName() == "" ||cert.getSubjectX500Principal().getName() == null) {
                if (debug){MainFrame.logger("    Subject was empty or null");}
                return Boolean.FALSE;
            }else {
                if (debug){MainFrame.logger("    Subject was ok:" + cert.getSubjectX500Principal().getName());}
                return Boolean.TRUE;
            }
        }catch (Exception e) {
            if (debug){MainFrame.logger("    parsing Subject field failed");}
            return Boolean.FALSE;
        }
    }

    /*
     *CSCA certificate should have country code field in the Subject
     * ERR:CSCA.SUB.10
     */
    final Boolean verifCSCACountryCodeInSubjectisPresent (X509CertificateObject cert){
        if (debug){MainFrame.logger("....starting verifCSCACountryCodeInSubjectisPresent");}
        String regex = "(.*)C\\=([^,]*)(.*)"; // regex tested again german CSCA
        Pattern r = Pattern.compile(regex);
        Matcher m = r.matcher(cert.getSubjectX500Principal().getName());
        if (m.find()) {
            if (debug){MainFrame.logger("    C field found:" + m.group(2));}
            if (m.group(2).length() == 2) {return Boolean.TRUE;}
            else {
                if (debug){MainFrame.logger("    C field found, but should be two letter code. was:|" + m.group(2) + "|");}
                return Boolean.FALSE;
            }
        }else {
            if (debug){MainFrame.logger("    no C field found, Subject was:" + cert.getSubjectX500Principal().getName());}
            return Boolean.FALSE;
        }
    }

    /*
     *CSCA certificate should have common name field in the Subject
     * WARN:CSCA.SUB.34//ERR:CSCA.SUB.34
     */
    final Boolean verifCSCACommonNameInSubjectisPresent (X509CertificateObject cert){
        if (debug){MainFrame.logger("....starting verifCSCACommonNameInSubjectisPresent");}
        String regex = "(.*)CN\\=([^,]*)(.*)";
        Pattern r = Pattern.compile(regex);
        Matcher m = r.matcher(cert.getSubjectX500Principal().getName());
        if (m.find()) {
            if (debug){MainFrame.logger("    CN field was:" + m.group(2));}
            return Boolean.TRUE;
        }else {
            if (debug){MainFrame.logger("    no CN field found, Subject was:" + cert.getSubjectX500Principal().getName());}
            return Boolean.FALSE;
        }
    }

    //TODO String encoding other than UTF8 or PrintableString ERR:CSCA.SUB.11


    //**********************************************SujectPublicKeyInfo TEST*******************************************
    //TODO ECDSA key has no explicit curve parameters, or has no co-factor, or is not in uncompressed format WARN:CSCA.PKI.47-WARN:CSCA.PKI.48-WARN:CSCA.PKI.49

    //************************************************Unique Identifier TEST*******************************************
    //TODO Unique Identifiers Is present ERR:CSCA.UID.15

    //************************************************Signature TEST***************************************************

    /*CSCA root must be selfsigned, in opposition to CSCA LINK
     *ERR:CSCA.SVA.66
     */
    final Boolean verifyCSCAisSelfSigned (X509CertificateObject cert){
        PublicKey pub = cert.getPublicKey();
        //CMSSignedData cms = new CMSSignedData(Base64.decode(envelopedData.getBytes()));
        //TODO

        return Boolean.FALSE;
    }

    //************************************************Extensions TEST**************************************************
    //TODO Default values are encoded ERR:CSCA.EXT.22


    //3.2 certificate extensions


    //*******************************************************AKI TEST**************************************************


    /*
     * CSCA Link certificate should have a AKI field
     * ERR:CSCA.AKI.14
     */
    final Boolean verifCSCALinkAKIisPresent(X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCALinkAKIisPresent");}
        if(isExtensionPresent(cert, AUTHORITY_KEY_IDENTIFIER)) {
            return Boolean.TRUE;
        }else{
            if (debug){MainFrame.logger("    NO AKI field found");}
            return Boolean.FALSE;
        }
    }

    /*
     * CSCA certificate should have a AKI field NOT tagged as critical
     * ERR:CSCA.AKI.18
     */
    final Boolean verifCSCAAKIisNotCritical(X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCAAKIisNotCritical");}
        if (isExtensionPresent(cert,AUTHORITY_KEY_IDENTIFIER)){
            if (isCritical(cert,AUTHORITY_KEY_IDENTIFIER)){
                if (debug){MainFrame.logger("    AKi field found to be critical");}
                return Boolean.FALSE;
            }else{
                if (debug){MainFrame.logger("    AKi field found to be NOT critical");}
                return Boolean.TRUE;
            }
        }else{
            if (debug){MainFrame.logger("    no AKi field present, so no possible testing on criticality");}
            if (debug){MainFrame.logger("        extension not required-> can be accepted");}
            return Boolean.TRUE;
        }

    }

    /*
     * the only difference with the above version is that in link AKI must be present and not critical, in root it can be absent
     * CSCA Link certificate should have a AKI field NOT tagged as critical
     * ERR:CSCA.AKI.18
     */
    final Boolean verifCSCALinkAKIisNotCritical(X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCALinkAKIisNotCritical");}
        if (isExtensionPresent(cert,AUTHORITY_KEY_IDENTIFIER)){
            if (isCritical(cert,AUTHORITY_KEY_IDENTIFIER)){
                if (debug){MainFrame.logger("    AKi field found to be critical");}
                return Boolean.FALSE;
            }else{
                if (debug){MainFrame.logger("    AKi field found to be NOT critical");}
                return Boolean.TRUE;
            }
        }else{
            if (debug){MainFrame.logger("    no AKi field present, so no possible testing on criticality");}
            return Boolean.FALSE;
        }

    }

    /*
     * CSCA certificate should have a Key identifier in its AKI field
     * ERR:CSCA.AKI.25
     */
    final Boolean verifCSCAAKIKeyIdentifierisPresent(X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCAAKIKeyIdentifierisPresent");}
        if (isExtensionPresent(cert,AUTHORITY_KEY_IDENTIFIER)){
            byte[] aki = cert.getExtensionValue(AUTHORITY_KEY_IDENTIFIER);
            byte[] akiOctet = DEROctetString.getInstance(aki).getOctets();
            AuthorityKeyIdentifier akiKey = AuthorityKeyIdentifier.getInstance(akiOctet);
            byte[] akiKeyReal = akiKey.getKeyIdentifier();


            if (akiKeyReal == null || akiKeyReal.length == 0){
                if (debug){MainFrame.logger("    Key identifier in AKI was null or empty");}
                return Boolean.FALSE;
            }else{
                //String akiInHexa = new String(Hex.encode(akiKeyReal));
                if (debug){MainFrame.logger("    Key identifier in AKI was found");}
                return Boolean.TRUE;
            }
        }else {return Boolean.FALSE;}
    }

    /*
     * CSCA certificate should have a AKI field with the same value as SKI field (because it's for CSCA ROOT not CSCA link)
     * ERR:CSCA.AKI.39
     */
    final Boolean verifCSCAAKIKeyIdentifierIsSameAsSKIKeyIdentifier(X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCAAKIKeyIdentifierIsSameAsSKIKeyIdentifier");}
        if (isExtensionPresent(cert,AUTHORITY_KEY_IDENTIFIER) && isExtensionPresent(cert,SUBJECT_KEY_IDENTIFIER)) {
            byte[] ski = cert.getExtensionValue(SUBJECT_KEY_IDENTIFIER);
            byte[] aki = cert.getExtensionValue(AUTHORITY_KEY_IDENTIFIER);
            byte[] skiOctet = DEROctetString.getInstance(ski).getOctets();
            byte[] akiOctet = DEROctetString.getInstance(aki).getOctets();
            SubjectKeyIdentifier skiKey = SubjectKeyIdentifier.getInstance(skiOctet);
            AuthorityKeyIdentifier akiKey = AuthorityKeyIdentifier.getInstance(akiOctet);
            byte[] skiKeyReal = skiKey.getKeyIdentifier();
            byte[] akiKeyReal = akiKey.getKeyIdentifier();

            if (Arrays.equals(skiKeyReal, akiKeyReal)) {
                if (debug){MainFrame.logger("    Key identifier in AKI and SKI were equals");}
                return Boolean.TRUE;
            } else {
                if (debug){MainFrame.logger("    Key identifier in AKI and SKI were different");}
                return Boolean.FALSE;
            }
        }else{
            if (debug){MainFrame.logger("    parsing Key identifier in AKI or SKI failed ");}
            return Boolean.FALSE;
        }
    }

    //*******************************************************SKI TEST**************************************************
    /*
     * CSCA certificate should have a SKI field NOT tagged as critical
     * ERR:CSCA.SKI.18
     */
    final Boolean verifCSCASKIisNotCritical(X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCASKIisNotCritical");}
        if (isExtensionPresent(cert, SUBJECT_KEY_IDENTIFIER)){
            if (isCritical(cert,SUBJECT_KEY_IDENTIFIER)){
                if (debug){MainFrame.logger("    SKi field found to be critical");}
                return Boolean.FALSE;
            }else{
                if (debug){MainFrame.logger("    SKi field found to be NOT critical");}
                return Boolean.TRUE;
            }
        }else{
            if (debug){MainFrame.logger("    no SKi field present, so no possible testing on criticality");}
            return Boolean.FALSE;
        }
    }

    /*
     * CSCA certificate should have a SKI field
     * ERR:CSCA.SKI.14
     */
    final Boolean verifCSCASKIisPresent(X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCASKIisPresent");}
        if(isExtensionPresent(cert,SUBJECT_KEY_IDENTIFIER)) {
            return Boolean.TRUE;
        }else{
            if (debug){MainFrame.logger("    NO SKi field found");}
            return Boolean.FALSE;
        }
    }

    /*
     * CSCA certificate should have a key identifier in the SKI field
     * ERR:CSCA.SKI.23
     */
    final Boolean verifCSCASKIHasKeyIdentifier (X509CertificateObject cert) {
        if (isExtensionPresent(cert, SUBJECT_KEY_IDENTIFIER)) {
            byte[] ski = cert.getExtensionValue(SUBJECT_KEY_IDENTIFIER);
            byte[] skiOctet = DEROctetString.getInstance(ski).getOctets();
            SubjectKeyIdentifier skiKey = SubjectKeyIdentifier.getInstance(skiOctet);
            byte[] skiKeyReal = skiKey.getKeyIdentifier();
            //String akiInHexa = new String(Hex.encode(akiKeyReal));

            if (skiKeyReal == null || skiKeyReal.length == 0) {
                if (debug){MainFrame.logger("    Key identifier in SKI was null or empty");}
                return Boolean.FALSE;
            } else {
                if (debug){MainFrame.logger("    Key identifier in SKI was found");}
                return Boolean.TRUE;
            }
        }else{return Boolean.FALSE;}
    }

    //**************************************************KeyUsage TEST**************************************************
    /*
     * CSCA certificate must have a KU field
     * ERR:CSCA.BKU.14
     */
    final Boolean verifCSCAKUisPresent(X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCAKUisPresent");}
        if (isExtensionPresent(cert,KEY_USAGE_IDENTIFIER)) {
            return Boolean.TRUE;
        }else{
            if (debug){MainFrame.logger("    NO KU extension found");}
            return Boolean.FALSE;
        }
    }

    /*
     * CSCA certificate must have in KU field, only certSign and crlSign
     * ERR:CSCA.BKU.20
     */
    final Boolean verifCSCAKUisOnlyCertAndCrlSign(X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCAKUisOnlyCertAndCrlSign");}
        if (isExtensionPresent(cert,KEY_USAGE_IDENTIFIER)) {
            //only allowed value are certSign and crlSign -> value 5&6
            boolean[] ku = cert.getKeyUsage();
            for (int i = 0; i < ku.length; i++) {
                if (debug) {
                    MainFrame.logger("    test:" + keyUsage[i] + "; iterator is:" + i);
                }
                if (ku[i]) {
                    if (debug) {
                        MainFrame.logger("        was true");
                    }
                    if (i == 5 || i == 6) {
                        continue; // c'est normal
                    } else {
                        return Boolean.FALSE;
                    } //c'est pas normal :)
                } else {
                    if (debug) {
                        MainFrame.logger("        was false");
                    }
                }
            }
            return Boolean.TRUE;
        }else{
            MainFrame.logger("    no KU field found to test value");
            return Boolean.FALSE;
        }
    }

    /*
     * CSCA certificate must have a KU field  tagged as critical
     * ERR:CSCA.BKU.19
     */
    final Boolean verifCSCAKUisCritical(X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCAKUisCritical");}
        if (isCritical(cert,KEY_USAGE_IDENTIFIER)){
            return Boolean.TRUE;
        }else{
            if (debug) {MainFrame.logger("    KU is NOT critical");}
            return Boolean.FALSE;
        }
    }

    //**************************************************PrivateKeyUsagePeriod TEST*************************************

    /*
     * CSCA certificate must have a Private Key Usage Period(PKUP) field NOT  tagged as critical
     * ERR:CSCA.PKU.18
     */
    final Boolean verifCSCAPKUPisNotCritical(X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCAPKUPisNotCritical");}
        if (isExtensionPresent(cert,PRIVATE_KEY_USAGE_PERIOD_IDENTIFIER)) {
            if (isCritical(cert, PRIVATE_KEY_USAGE_PERIOD_IDENTIFIER)) {
                if (debug){MainFrame.logger("    PKUP field was critical");}
                return Boolean.FALSE;
            } else {
                if (debug){MainFrame.logger("    PKUP field is not critical");}
                return Boolean.TRUE;
            }
        }else{
            if (debug){MainFrame.logger("    PKUP field not found, so no possible testing on criticality");}
            return Boolean.FALSE;
        }
    }

    /*
     * CSCA certificate must have a Private Key Usage Period(PKUP) field and the field notBefore&notAfter have to be there also
     * ERR:CSCA.PKU.17
     */
    final Boolean verifCSCAPKUPisPresentAlongWithNotBeforeAndNotAfter(X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCAPKUPisPresentAlongWithNotBeforeAndNotAfter");}
        if(isExtensionPresent(cert, PRIVATE_KEY_USAGE_PERIOD_IDENTIFIER)) {
            Date notAfter = cert.getNotAfter();
            Date notBefore = cert.getNotBefore();
            if (debug){MainFrame.logger("    NotBefore was:" + notBefore.toString());}
            if (debug){MainFrame.logger("    NotAfter was:" + notAfter.toString());}
            if (notAfter != null && notBefore != null){
                return Boolean.TRUE;
            }else{
                if (debug){MainFrame.logger("    either NotBefore or NotBefore are null");}
                return Boolean.FALSE;
            }
        }else{return Boolean.FALSE;}
    }
    //TODO Is not encoded as generalizedTime ERR:CSCA.PKU.9

    //**************************************************CertificatePolicies TEST***************************************
    /*
     * CSCA certificate should have a Certificate Policies field NOT tagged as critical
     * ERR:CSCA.CEP.18
     */
    final Boolean verifCSCACertPolicyisNotCritical(X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCACertPolicyisNotCritical");}
        if (isExtensionPresent(cert,CERTIFICATES_POLICIES_IDENTIFIER)) {
            if (isCritical(cert, CERTIFICATES_POLICIES_IDENTIFIER)) {
                if (debug){MainFrame.logger("    certificates policies are critical");}
                return Boolean.FALSE;
            } else {
                if (debug){MainFrame.logger("    certificates policies are NOT critical");}
                return Boolean.TRUE;
            }
        }else{
            if (debug){MainFrame.logger("    Certificates policies extension NOT found, so no possible testing on criticality");}
            return Boolean.FALSE;
        }
    }


    //*******************************************************PolicyMappings TEST***************************************
    /*
     * CSCA certificate should NOT have a Policy Mappings field
     * ERR:CSCA.POM.15
     */
    final Boolean verifCSCAPolicyMappingisNotPresent(X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCAPolicyMappingisNotPresent");}
        if (isExtensionPresent(cert,POLICY_CONSTRAINTS_IDENTIFIER)) {
            if (debug){MainFrame.logger("    Policy Mappings extension is present");}
            return Boolean.FALSE;
        }else{return Boolean.TRUE;}
    }

    //***********************************************SubjectAlternativeName TEST***************************************
    /*
     * CSCA certificate should have a SubjectAlternativesName field
     * WARN::CSCA.SAN.14
     */
    final Boolean verifCSCASANisPresent(X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCASANisPresent");}
        if (isExtensionPresent(cert, SUBJECT_ALTERNATIVE_NAME_IDENTIFIER)) {
            return Boolean.TRUE;
        }else{
            if (debug){MainFrame.logger("    SAN extension is NOT present");}
            return Boolean.FALSE;
        }
    }

    /*
     * CSCA certificate should have a SubjectAlternativesName field NOT tagged as critical
     * ERR:CSCA.SAN.18
     */
    final Boolean verifCSCASANisNotCritical(X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCASANisNotCritical");}
        if (isExtensionPresent(cert,SUBJECT_ALTERNATIVE_NAME_IDENTIFIER)) {
            if (isCritical(cert, SUBJECT_ALTERNATIVE_NAME_IDENTIFIER)) {
                if (debug){MainFrame.logger("    SAN extension is critical");}
                return Boolean.FALSE;
            } else {
                return Boolean.TRUE;
            }
        }else{
            if (debug){MainFrame.logger("    SAN extension is NOT present, so no possible testing on criticality");}
            return Boolean.FALSE;
        }
    }

    //************************************************IssuerAlternativeName TEST***************************************
    /*
     * CSCA certificate should have a IssuerAlternativesName field NOT tagged as critical
     * ERR:CSCA.IAN.18
     */
    final Boolean verifCSCAIANisNotCritical(X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCAIANisNotCritical");}
        if (isExtensionPresent(cert,ISSUER_ALTERNATIVE_NAME_IDENTIFIER)) {
            if (isCritical(cert,ISSUER_ALTERNATIVE_NAME_IDENTIFIER)) {
                if (debug){MainFrame.logger("    IAN extension is critical");}
                return Boolean.FALSE;
            } else {
                return Boolean.TRUE;
            }
        }else{
            if (debug){MainFrame.logger("    IAN extension is NOT present, so no possible testing on criticality");}
            return Boolean.FALSE;
        }
    }

    /*
     * CSCA certificate should have a IssuerAlternativesName field
     * WARN:CSCA.IAN.14 ERR:CSCA.IAN.14
     */
    final Boolean verifCSCAIANisPresent(X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCAIANisPresent");}
        if (isExtensionPresent(cert, ISSUER_ALTERNATIVE_NAME_IDENTIFIER)) {
            return Boolean.TRUE;
        }else{
            if (debug){MainFrame.logger("    IAN extension is NOT present");}
            return Boolean.FALSE;
        }
    }

    /*
     *CSCA certificate should have same content of SAN and IAN (as  CSCA ROOT, not CSCA LINK)
     * WARN:CSCA.IAN.57 ERR:CSCA.IAN.57
     */
    final Boolean verifCSCAIANisSameAsSAN (X509CertificateObject cert){// TODO: 3/6/2017
        if (debug){MainFrame.logger("....starting verifCSCAIANisSameAsSAN");}
        if (isExtensionPresent(cert,ISSUER_ALTERNATIVE_NAME_IDENTIFIER) && isExtensionPresent(cert,SUBJECT_ALTERNATIVE_NAME_IDENTIFIER)) {
            Collection collIAN;
            Collection collSAN;
            try {
                collIAN = cert.getIssuerAlternativeNames();
                collSAN = cert.getSubjectAlternativeNames();
                if (debug){MainFrame.logger("      IAN contains "+collIAN.size()+"entry(ies)");}
                if (debug){MainFrame.logger("      SAN contains "+collSAN.size()+"entry(ies)");}

                if (collIAN != null && collSAN != null) {

                    if (collIAN.size() == collSAN.size()) {   //if same size, we compare content
                        Iterator itIan = collIAN.iterator();
                        while (itIan.hasNext()) {
                            if (debug){MainFrame.logger("      first while round on IAN:");}
                            List lstIan = (List)itIan.next();
                            int Oid= ((Integer)lstIan.get(0)).intValue();
                            if (debug){MainFrame.logger("      |->OID was:"+Oid);}
                            String issuerAltName = (String) lstIan.get(1);
                            if (debug){MainFrame.logger("      |->content was:"+issuerAltName);}
                            //ASN1Sequence asn1 = ASN1Sequence.getInstance(new ASN1InputStream(new ByteArrayInputStream(issuerAltName)));
                            Iterator itSan = collSAN.iterator();
                            boolean found= false;
                            while (itSan.hasNext()) {
                                if (debug){MainFrame.logger("          compared with");}
                                List lstSan = (List)itSan.next();
                                int OidSan= ((Integer)lstSan.get(0)).intValue();
                                if (debug){MainFrame.logger("          |->OID was:"+OidSan);}
                                String subjectAltName = (String) lstSan.get(1);
                                if (debug){MainFrame.logger("          |->content was:"+issuerAltName);}
                                if (Objects.equals(issuerAltName, subjectAltName)) {
                                    if (debug){MainFrame.logger("      |->found the same content in SAN");}
                                    found=true;
                                    break;
                                }
                            }
                            if (!found){
                                if (debug){MainFrame.logger("          comparison failed, exiting this controls");}
                                return Boolean.FALSE;
                            }
                        }
                        return Boolean.TRUE;
                    } else {
                        return Boolean.FALSE;
                    }// else it cannot be equals
                }else {
                    if (debug){MainFrame.logger("IAN and/or SAN was found to be null, cannot compare properly");}
                    return Boolean.TRUE;// should it be false? but another controls function is here to test that these field are present...
                }

            }catch (CertificateParsingException cpe){
                MainFrame.logger("    ERR: Exception while parsing certificate: should not happens as we tested the field before using it"+cpe.getMessage());
                return Boolean.FALSE;
            }catch (NullPointerException npe){
                MainFrame.logger("    ERR: Equals failed, while comparing Null object:"+npe.getMessage());
                return Boolean.FALSE;
            }catch (Exception e){
                MainFrame.logger("    ERR: Exception unhandled:"+e.getMessage());
                return Boolean.FALSE;
            }
        }else {
            MainFrame.logger("    ERR: Field IAN or SAN are missing, cannot verify");
            return Boolean.FALSE;
        }
    }
    //*******************************************SubjectDirectoryAttributes TEST***************************************
    /*
     * CSCA certificate should have a SubjectDirectoryAttributes field NOT tagged as critical (if present)
    * ERR:CSCA.SDA.15
    */
    final Boolean verifCSCASubjectDirAttributesisNotCritical(X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCASubjectDirAttributesisNotCritical");}
        if (isExtensionPresent(cert,SUBJECT_DIRECTORY_ATTRIBUTES_IDENTIFIER)) {
            if (isCritical(cert,SUBJECT_DIRECTORY_ATTRIBUTES_IDENTIFIER)) {
                if (debug){MainFrame.logger("    subject dir Attributes extension is critical");}
                return Boolean.FALSE;
            } else {
                return Boolean.TRUE;
            }
        }else{
            if (debug){MainFrame.logger("    subject dir Attributes extension NOT found, so no possible testing on criticality");}
            if (debug){MainFrame.logger("        extension not required-> can be accepted");}
            return Boolean.TRUE;// we return true because nobody ask for this, this must just not be critical, but can be absent also
        }
    }
    //******************************************************BasicConstraint TEST***************************************

    /*CSCA certificate must have the Basic Constraintes field  present
     *ERR:CSCA.BAC.14
     */
    final Boolean verifCSCABasicConstraintsIsPresent (X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCABasicConstraintsIsPresent");}
        if (cert.getBasicConstraints() >= 0) {// if not present or end-entity certificate, it returns -1
            return Boolean.TRUE;
        }else {
            if (debug){MainFrame.logger("    Basic constraints extension NOT found");}
            return Boolean.FALSE;
        }
    }

    /*CSCA certificate must have the Basic Constraints field  marked as critical
     *ERR:CSCA.BAC.19
     */
    final Boolean verifCSCABasicConstraintsIsCritical (X509CertificateObject cert){
        if (debug){MainFrame.logger("....starting verifCSCABasicConstraintsIsCritical");}
        if (isExtensionPresent(cert,BASIC_CONSTRAINTS_IDENTIFIER)) {
            if (isCritical(cert,BASIC_CONSTRAINTS_IDENTIFIER)) {
                if (debug){MainFrame.logger("    BC extension is critical");}
                return Boolean.TRUE;
            } else {
                return Boolean.FALSE;
            }
        }else{
            if (debug){MainFrame.logger("    BC extension NOT found, so no possible testing on criticality");}
            return Boolean.FALSE;
        }
    }

    //TODO CA bit is not asserted ERR:CSCA.BAC.24


    /*CSCA certificate must have the pathLength variable in Basic Constraints field  set to 0
     *ERR:CSCA.BAC.14
     */
    final Boolean verifCSCABasicConstraintsPathLengthIsZero (X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCABasicConstraintsPathLengthIsZero");}
        if (cert.getBasicConstraints() == 0) {
            return Boolean.TRUE;
        }else {return Boolean.FALSE;}
    }


    //******************************************************NameConstraints TEST***************************************
    /*CSCA certificate must not contains the Name Constraints field
     *ERR:CSCA.NAC.15
     */
    final Boolean verifCSCANAmeConstraintsIsNotPresent (X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCANAmeConstraintsIsNotPresent");}
        if (isExtensionPresent(cert,NAME_CONSTRAINTS_IDENTIFIER)) {
            if (debug){MainFrame.logger("    Name constraints extension is present");}
            return Boolean.FALSE;
        }else {return Boolean.TRUE;}
    }
    //****************************************************PolicyConstraints TEST***************************************
    /*CSCA certificate must not contains the Policy Constraints field
     *ERR:CSCA.POC.15
     */
    final Boolean verifCSCAPolicyConstraintsIsNotPresent (X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCAPolicyConstraintsIsNotPresent");}
        if (isExtensionPresent(cert,POLICY_CONSTRAINTS_IDENTIFIER)) {
            if (debug){MainFrame.logger("    Poilicy constraints extension is present");}
            return Boolean.FALSE;
        }else {return Boolean.TRUE;}
    }
    //*****************************************************ExtendedKeyUsage TEST***************************************
    /*CSCA certificate must not contains the EKU field
     *ERR:CSCA.EKU.15
     */
    final Boolean verifCSCAEKUIsNotPresent (X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCAEKUIsNotPresent");}
        if (isExtensionPresent(cert, EXTENDED_KEY_USAGE_IDENTIFIER)) {
            if (debug){MainFrame.logger("    EKU extension is present");}
            return Boolean.FALSE;
        }else {return Boolean.TRUE;}
    }
    //*************************************************CRLDistributionPoint TEST***************************************
    /*CSCA certificate should contain the CDP field, but NOt tagged as critical
     *ERR:CSCA.CDP.18
     */
    final Boolean verifCSCACDPIsNotCritical (X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCACDPIsNotCritical");}
        if (isExtensionPresent(cert,CRL_DISTRIBUTION_POINT_IDENTIFIER)) {
            if (isCritical(cert,CRL_DISTRIBUTION_POINT_IDENTIFIER)) {
                if (debug){MainFrame.logger("    CDP extension is critical");}
                return Boolean.FALSE;
            } else {
                return Boolean.TRUE;
            }
        }else{
            if (debug){MainFrame.logger("    CDP extension is NOT present, so no possible testing on criticality");}
            return Boolean.FALSE;
        }
    }

    /*CSCA certificate must  contains the CDP field
     *WARN:CSCA.CDP.14 ERR:CSCA.CDP.14
     */
    final Boolean verifCSCACDPIsPresent (X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCACDPIsPresent");}
        if (isExtensionPresent(cert, CRL_DISTRIBUTION_POINT_IDENTIFIER)) {
            if (debug) {MainFrame.logger("    the CDP extension was found");}
            return Boolean.TRUE;
        }else {
            if (debug) {MainFrame.logger("    the CDP extension was NOT found");}
            return Boolean.FALSE;
        }
    }

    //*****************************************************InhibitAnyPolicy TEST***************************************
    /*CSCA certificate must  NOT contains the INHIBIT ANY POLICY field
     *ERR:CSCA.IAP.15
     */
    final Boolean verifCSCAInhibitAnyPolicyisNotPresent (X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCAInhibitAnyPolicyisNotPresent");}
        if (isExtensionPresent(cert,INHIBIT_ANY_POLICY_IDENTIFIER)) {
            if (debug) {MainFrame.logger("    the inhibit any policy extension was found");}
            return Boolean.FALSE;
        }else {
            if (debug) {MainFrame.logger("    the inhibit any policy extension was NOT found");}
            return Boolean.TRUE;
        }
    }

    //**********************************************************FreshestCRL TEST***************************************
    /*CSCA certificate must  NOT contains the FRESHESTCRL field
     *ERR:CSCA.FCR.15
     */
    final Boolean verifCSCAFreshestCRLisNotPresent (X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCAFreshestCRLisNotPresent");}
        if (isExtensionPresent(cert, FRESHESTCRL_IDENTIFIER)) {
            if (debug) {MainFrame.logger("    the freshest CRL extension was found");}
            return Boolean.FALSE;
        }else {
            if (debug) {MainFrame.logger("    the freshest CRL extension was NOT found");}
            return Boolean.TRUE;
        }
    }

    //********************************************PrivateInternetExtensions TEST***************************************
    /*CSCA certificate can contain the PrivateInternetExtensions field, but then it should NOT be tagged as critical
     *ERR:CSCA.PIE.18
     */
    final Boolean verifCSCAPrivateInternetExtensionisNotCritical (X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCAPrivateInternetExtensionisNotCritical");}
        if (isExtensionPresent(cert,PRIVATE_NTERNET_EXTENSION_IDENTIFIER)) {
            if (isCritical(cert,PRIVATE_NTERNET_EXTENSION_IDENTIFIER)) {
                if (debug){MainFrame.logger("    private Internet extension is critical");}
                return Boolean.FALSE;
            } else {
                return Boolean.TRUE;
            }
        }else{
            if (debug){MainFrame.logger("    private Internet extension not found, so no possible testing on criticality");}
            if (debug){MainFrame.logger("        extension not required-> can be accepted");}
            return Boolean.TRUE;
        }
    }

    //***********************************************NetscapeCertExtensions TEST***************************************
    /*CSCA certificate must  NOT contains the NetscapeCertExtensions field
     *ERR:CSCA.FCR.15
     */
    final Boolean verifCSCANetscapeCertExtensionisNotPresent (X509CertificateObject cert) {
        if (debug){MainFrame.logger("....starting verifCSCANetscapeCertExtensionisNotPresent");}
        if (isExtensionPresent(cert,NETSCAPE_CERT_EXTENSIONS_IDENTIFIER)) {
            if (debug){MainFrame.logger("    Netscape cert extension is present");}
            return Boolean.FALSE;
        }else {
            if (debug){MainFrame.logger("    Netscape cert extension is NOT present");}
            return Boolean.TRUE;
        }
    }

    //**************************************************************DS verification function***************************

    /*DS certificate must have a issuer field
     *ERR:DSC.ISS.14
     */
    final Boolean  verifDSissuerisPresent(X509CertificateObject cert){
        if (debug){MainFrame.logger("....starting verifDSissuer is present");}
        try {
            if (cert.getIssuerX500Principal().getName() == "") {
                return Boolean.FALSE;
            }else {
                return Boolean.TRUE;
            }
        }catch (Exception e) {
            return Boolean.FALSE;
        }
    }

    /*DS certificate need a C field in its issuer
     *ERR:DSC.ISS.10
     */
    final Boolean verifDSCountryCodeInIssuerisPresent (X509CertificateObject cert){
        if (debug){MainFrame.logger("....starting verifDSCountryCodeInIssuerisPresent");}
        String regex = "(.*)C\\=([^,]*)(.*)"; // regex tested again german CSCA
        Pattern r = Pattern.compile(regex);
        Matcher m = r.matcher(cert.getIssuerX500Principal().getName());
        if (m.find()) {
            if (debug){MainFrame.logger("    C field was:" + m.group(2));}
            if (m.group(2).length() == 2) {return Boolean.TRUE;}
            else {return Boolean.FALSE;}
        }else {return Boolean.FALSE;}
    }


    /*DS certificate must contains the AKI field
    *ERR:DSC.AKI.14
    */
    final Boolean verifDSAKIIsPresent (X509CertificateObject cert) {
        if (isExtensionPresent(cert,AUTHORITY_KEY_IDENTIFIER)) {
            return Boolean.TRUE;
        }else {return Boolean.FALSE;}
    }

    /*
     * DS certificate must have in KU field, only digitalSignature
     * ERR:DSC.BKU.21
     */
    final Boolean verifDSKUisOnlyDigitalSignature(X509CertificateObject cert) {
        if (debug){MainFrame.logger(".... starting verifDSKUisOnlyDigitalSignature");}
        String msg="";
        //only allowed value is digital Signature -> value 0
        boolean[] ku = cert.getKeyUsage();
        for (int i =0;i< ku.length;i++) {
            if (debug){MainFrame.logger("    test:" + keyUsage[i] + ", iterator is:" + i);}
            if (ku[i]) {
                if (debug){MainFrame.logger("        was true");}
                if (i ==0) {
                    continue; // c'est normal
                }else{return Boolean.FALSE;} //c'est pas normal :)
            }else{
                if (debug){MainFrame.logger("        was false");}
            }
        }
        return Boolean.TRUE;
    }

    /*DS certificate must not have the Basic Constraintes field  present
     *ERR:DSC.BAC.15
     */
    final Boolean verifDSBasicConstraintsIsNotPresent (X509CertificateObject cert) {
        if (cert.getBasicConstraints() >= 0) {// if not present or end-entity certificate, it returns -1
            return Boolean.FALSE;
        } else {
            return Boolean.TRUE;
        }
    }

    /*DS certificate must have a Document type field  present
     *WARN:DSC.DTL.14 ERR:DSC.DTL.14
     */
    final Boolean verifDSDocumentTypeisPresent (X509CertificateObject cert) {
        if (debug){MainFrame.logger("... starting verifDSDocumentTypeisPresent");}
        if (isExtensionPresent(cert,DOCUMENT_TYPE_IDENTIFIER)) {
            if (debug) {MainFrame.logger("    \"Document type\" extension was found");}
            return Boolean.TRUE;
        } else {
            return Boolean.FALSE;
        }
    }

    //*************************************************************CRL verification function***************************

    //********************************************************************************Version
    /* the CRL Version should be  2 (= version 3)
     * ERR:CRL.VER.13
    */
    final Boolean verifCRLisVersion3(X509CRLObject crl){
        if (debug){MainFrame.logger("....starting verifCSCAVersion3");}
        if (crl.getVersion() == 2) { // eh oui car V3 = 2... :)
            return Boolean.TRUE;
        }else { return Boolean.FALSE;}
    }

    //********************************************************************************Issuer
    /* the CRL issuer must be present
     * ERR:CRL.ISS.14
    */
    final Boolean verifCRLIssuerisPresent (X509CRLObject crl){
        if (debug){MainFrame.logger("....starting verifCRLIssuerisPresent");}
        try {
            if (crl.getIssuerX500Principal().getName() != null && crl.getIssuerX500Principal().getName() != "") {
                return Boolean.TRUE;
            } else {return Boolean.FALSE;}
        }catch (Exception e) {
            return Boolean.FALSE;
        }
    }

    /* the Country code in issuer  field of the CRL must be present
     * ERR:CRL.ISS.10
    */
    final Boolean verifCRLCountryCodeInIssuerisPresent (X509CRLObject crl){
        if (debug){MainFrame.logger("....starting verifCRLCountryCodeInIssuerisPresent");}
        String regex = "(.*)C\\=([^,]*)(.*)";
        Pattern r = Pattern.compile(regex);
        Matcher m = r.matcher(crl.getIssuerX500Principal().getName());
        if (m.find()) {
            if (debug){MainFrame.logger("    C field was:" + m.group(2));}
            if (m.group(2).length() == 2) {return Boolean.TRUE;}
            else {return Boolean.FALSE;}
        }else {return Boolean.FALSE;}
    }

    //TODO
    /* the issuer field of the crl cannot have Invalid String encoding
     * ERR:CRL.ISS.11
    */

    //TODO
    /*Encoding may be PrintableString
     * WARN:CRL.ISS.11
     */

    //***************************************************************************thisUpdate
    /* the field thisUpdate of the crl must be present
     *  ERR:CRL.TUP.14
    */
    final Boolean verifCRLthisUpdateisPresent (X509CRLObject crl){
        if (debug){MainFrame.logger("....starting verifCRLthisUpdateisPresent");}
        try {
            Date thisUpdate = null;
            thisUpdate = crl.getThisUpdate();
            if (thisUpdate !=null) {
                return Boolean.TRUE;
            } else {return Boolean.FALSE;}
        }catch (Exception e) {
            return Boolean.FALSE;
        }
    }

    //TODO
    /* the thisUpdate Date less the 2050 must not be encoded as GeneralizedTime
     * ERR:CRL.TUP.4
    */

    //TODO
    /* the thisUpdate Date greater than 2049 must not be encoded as UTCTime
     * ERR:CRL.TUP.5
    */

    //TODO
    /* thisUpdate field cannot have fractional seconds if using Generalized Time
    *ERR:CRL.TUP.6
    */

    //TODO
    /* the UTCTime encoding of thisUpdate field cannot be wrong
     * ERR:CRL.TUP.7
    */

    //TODO
    /* the Generalized Time encoding of thisUpdate field cannot be wrong
     * ERR:CRL.TUP.8
    */

    //*****************************************************************************nextUpdate
    /* the field nextUpdate of the crl must be present
     * ERR:CRL.NUP.14
    */
    final Boolean verifCRLnextUpdateisPresent (X509CRLObject crl){
        if (debug){MainFrame.logger("....starting verifCRLnextUpdateisPresent");}
        try {
            Date nextUpdate = null;
            nextUpdate = crl.getNextUpdate();
            if (nextUpdate !=null) {
                return Boolean.TRUE;
            } else {return Boolean.FALSE;}
        }catch (Exception e) {
            return Boolean.FALSE;
        }
    }

    //TODO
    /* the nextUpdate Date less the 2050 cannot be encoded  GeneralizedTime
     * ERR:CRL.NUP.4
    */

    //TODO
    /* the nextUpdate Date greater than 2049 cannot be encoded as UTCTime
     * ERR:CRL.NUP.5
    */

    //TODO
    /*the nextUpdate cannot have fractional seconds if using Generalized Time
     * ERR:CRL.NUP.6
    */

    //TODO
    /* the UTCTime encoding of the nextUpdate field cannot be wrong
     * ERR:CRL.NUP.7
    */

    //TODO
    /* the Generalized Time encoding of the nextUpdate field cannot be wrong
     * ERR:CRL.NUP.8
    */

    //****************************************************************************revoked certificates
    //TODO
    /* the revokedCertificates field must be present and not empty
     * ERR:CRL.REC.16
    */

    //*******************************************************************************extensions??
    //TODO
    /*Default values of Extensions are encoded
     * ERR:CRL.EXT.22
    */

    //*******************************************************************************CRL Extensions

    //*******************************************************AKI
    /*AuthorityKeyIdentifier must be  present
     * ERR:CRL.AKI.14
     */
    final Boolean verifCRLAKIisPresent(X509CRLObject crl) {
        if (debug){MainFrame.logger("....starting verifCRLAKIisPresent");}
        if (crlIsExtensionPresent(crl,AUTHORITY_KEY_IDENTIFIER)){
            return Boolean.TRUE;
        }else{
            return Boolean.FALSE;
        }
    }

    /*AKI must not be tagged as critical
     *ERR:CRL.AKI.18
     */
    final Boolean verifCRLAKIisNotCritical(X509CRLObject crl) {
        if (debug){MainFrame.logger("....starting verifCRLAKIisNotCritical");}
        if (crlIsCritical(crl,AUTHORITY_KEY_IDENTIFIER)){
            return Boolean.FALSE;
        }else{
            return Boolean.TRUE;
        }
    }

    /*AKI must have  key identifier
     * ERR:CRL.AKI.23
     */
    final Boolean verifCRLAKIKeyIdentifierisPresent(X509CRLObject crl) {
        if (debug){MainFrame.logger("....starting verifCRLAKIKeyIdentifierisPresent");}
        if (crlIsExtensionPresent(crl,AUTHORITY_KEY_IDENTIFIER)){
            byte[] aki = crl.getExtensionValue(AUTHORITY_KEY_IDENTIFIER);
            byte[] akiOctet = DEROctetString.getInstance(aki).getOctets();
            AuthorityKeyIdentifier akiKey = AuthorityKeyIdentifier.getInstance(akiOctet);
            byte[] akiKeyReal = akiKey.getKeyIdentifier();

            if (akiKeyReal == null || akiKeyReal.length == 0){
                return Boolean.FALSE;
            }else{
                return Boolean.TRUE;
            }
        }else {return Boolean.FALSE;}
    }

    //******************************************************IssuerAlternativeName
    /* the IAN must not be tagged as critical
    *ERR:CRL.IAN.18
    */
    final Boolean verifCRLIANisNotCritical(X509CRLObject crl) {
        if (debug){MainFrame.logger("....starting verifCRLIANisNotCritical");}
        if (crlIsCritical(crl,ISSUER_ALTERNATIVE_NAME_IDENTIFIER)) {
            return Boolean.FALSE;
        }else{return Boolean.TRUE;}
    }

    //*******************************************************CRL number
    /* the crl number must be present
     * ERR:CRL.CRN.14
     */
    final Boolean verifCRLNumberisPresent(X509CRLObject crl) {
        if (debug){MainFrame.logger("....starting verifCRLNumberisPresent");}
        byte[] crlNumber = crl.getExtensionValue(CRL_NUMBER_IDENTIFIER);
        String crlNumberAsHexa = new BigInteger(crlNumber).toString(16);
        if (debug){ MainFrame.logger("         the crl number in hexa is:" + crlNumberAsHexa);}
        if (crlNumberAsHexa != null && crlNumberAsHexa != "") {
            return Boolean.TRUE;
        }else{return Boolean.FALSE;}
    }

    //TODO
    /* the crl number must  be encoded as 2’s complement
     * ERR:CRL.CRN.1
     */

    //TODO
    /* the crl number must use the smallest number of Octets representation
     * ERR:CRL.CRN.2
     */

    //TODO
    /* the crl number must NOT be Greater than 20 Octets
     * ERR:CRL.CRN.3
     */


    /* the crl number cannot be a Negative value
     * ERR:CRL.CRN.0
     */
    final Boolean verifCRLNumberIsNotNegative (X509CRLObject crl){
        if (debug){MainFrame.logger("....starting verifCRLNumberIsNotNegative");}
        byte[] crlNumber = crl.getExtensionValue(CRL_NUMBER_IDENTIFIER);
        BigInteger crlNumber_int = new BigInteger(crlNumber);
        if (crlNumber_int.signum() == 1){ // signum returns 1 if bigger than zero
            if (debug){ MainFrame.logger("         the crl number was positiv");}
            return Boolean.TRUE;
        }else{ return Boolean.FALSE;}
    }

    /* the crl number cannot be tagged as critical
     *ERR:CRL.CRN.18
     */
    final Boolean verifCRLnumberIsNotCritical (X509CRLObject crl){
        if (debug){MainFrame.logger("....starting verifCRLnumberIsNotCritical");}
        if (crlIsCritical(crl, CRL_NUMBER_IDENTIFIER)) {
            return Boolean.FALSE;
        }else{return Boolean.TRUE;}
    }

    //*********************************************************Delta CRL indicator
    /* the delta crl indicator must NOT be present
     * ERR:CRL.DCR.15
     */
    final Boolean verifCRLDeltaIndicatorIsNotPresent (X509CRLObject crl){
        if (debug){MainFrame.logger("....starting verifCRLDeltaIndicatorIsNotPresent");}
        if (crl.getExtensionValue(CRL_DELTA_INDICATOR_IDENTIFIER) != null){
            return Boolean.FALSE;
        }else{return Boolean.TRUE;}
    }

    //***********************************************************Issuing distribution point
    /* the issuing distribution point must NOT be present
     * ERR:CRL.IDP.15
     */
    final Boolean verifCRLIssuingDPIsNotPresent (X509CRLObject crl){
        if (debug){MainFrame.logger("....starting verifCRLIssuingDPIsNotPresent");}
        if (crl.getExtensionValue(CRL_ISSUING_DISTRIBUTION_POINT_IDENTIFIER) != null){
            return Boolean.FALSE;
        }else{return Boolean.TRUE;}
    }

    //************************************************************Freshest CRL
    /* the freshest CRL field must NOT be present
     * ERR:CRL.FCR.15
     */
    final Boolean verifCRLFreshestCrlIsNotpresent (X509CRLObject crl){
        if (debug){MainFrame.logger("....starting verifCRLFreshestCrlIsNotpresent");}
        if (crl.getExtensionValue(FRESHESTCRL_IDENTIFIER) != null){
            return Boolean.FALSE;
        }else{return Boolean.TRUE;}
    }

    //***********************************************************CRL Entry  extensions
    /*
     * the CRL entry reason code must not be tagged as critical
     * WARN:CRL.REA.18 ERR:CRL.REA.18
     */
    final Boolean verifCRLEntryReasonCodeIsNotCritical (X509CRLObject crl){
        if (debug){MainFrame.logger("....starting verifCRLEntryReasonCodeIsNotCritical");}
        if (loopIsAnyCRLExtensionCritical(crl,CRL_ENTRY_REASON_CODE_IDENTIFIER)){
            return Boolean.FALSE;
        }else{
            return Boolean.TRUE;
        }

    }

    /*
     * the CRL entry Hold instuctions code must not be tagged as critical
     * WARN:CRL.HIC.18 ERR:CRL.HIC.18
     */
    final Boolean verifCRLEntryHoldInstuctionCodeIsNotCritical (X509CRLObject crl){
        if (debug){MainFrame.logger("....starting verifCRLEntryHoldInstuctionCodeIsNotCritical");}
        if (loopIsAnyCRLExtensionCritical(crl,CRL_ENTRY_HOLD_INSTRUCTION_CODE_IDENTIFIER)){
            return Boolean.FALSE;
        }else{
            return Boolean.TRUE;
        }

    }

    /*
     * the CRL entry Invalidity date must not be tagged as critical
     * WARN:CRL.IND.18 ERR:CRL.IND.18
     */
    final Boolean verifCRLEntryInvalidityDateIsNotCritical (X509CRLObject crl){
        if (debug){MainFrame.logger("....starting verifCRLEntryInvalidityDateIsNotCritical");}
        if (loopIsAnyCRLExtensionCritical(crl,CRL_ENTRY_INVALIDITY_DATE_IDENTIFIER)){
            return Boolean.FALSE;
        }else{
            return Boolean.TRUE;
        }

    }

    //the invalidity date must not be generalized time ERR:CRL.IND.9 ERR:CRL.IND.9

    /*
     * the CRL entry certificate issuer  cannot be present
     * WARN:CRL.CEI.15 ERR:CRL.CEI.15
     */
    final Boolean verifCRLEntryCertificateIssuerIsNotPresent (X509CRLObject crl){
        if (debug){MainFrame.logger("....starting verifCRLEntryCertificateIssuerIsNotPresent");}
        Set revokedCert = crl.getRevokedCertificates();
        if (revokedCert!=null){
            Iterator it = revokedCert.iterator();
            if (debug){MainFrame.logger("        list of revoked certs was not null: " + revokedCert.size() + " certs found");}
            int i=0;
            while (it.hasNext()){
                i++;
                if (debug){MainFrame.logger("            certificate #" + i);}
                X509CRLEntry entry = (X509CRLEntry)it.next();
                    // on a toujours une exception, il semble essayer une case trop loin donc->
                    if (entry != null) {
                        if (debug) {
                            MainFrame.logger("            checking CRL Entry:");
                            MainFrame.logger("              " + entry.getSerialNumber().toString());
                        }
                        if (crlExtensionisPresent(entry, CRL_ENTRY_CERTIFICATE_ISSUER_IDENTIFIER)) {
                            if (debug) {
                                MainFrame.logger("            found a certificate issuer extension  for one CRL Entry:" + entry.getSerialNumber().toString());
                            }
                            return Boolean.FALSE;
                        }
                    }else {if (debug){MainFrame.logger("            DEBUG: iterator was null, this if saved your a**");}}
            }
        }else{if (debug){MainFrame.logger("        list of revoked certs was empty/null");}}
        return Boolean.TRUE;

    }

    //utility function:

    /*
     *merci http://www.programcreek.com/java-api-examples/index.php?source_dir=cas-server-4.0.1-master/cas-server-support-x509/src/main/java/org/jasig/cas/adaptors/x509/authentication/handler/support/X509CredentialsAuthenticationHandler.java
     *
     */

    private boolean isCritical(final X509CertificateObject certificate, final String extensionOid) {
        final Set<String> criticalOids = certificate.getCriticalExtensionOIDs();
        if (criticalOids == null || criticalOids.isEmpty()) {
            return false;
        }
        return criticalOids.contains(extensionOid);
    }



    /*
     * go trouver si une extension est présente
     */
    private boolean isExtensionPresent (X509CertificateObject certificate,String extensionOid) {
        final Set<String>  nonCriticalExtensionOIDs = certificate.getNonCriticalExtensionOIDs();
        final Set<String> criticalExtensionOids = certificate.getCriticalExtensionOIDs();
        // on cherche parmi les extension critiques et non critiques, et on est censé le trouver.
        if (nonCriticalExtensionOIDs.contains(extensionOid) || criticalExtensionOids.contains(extensionOid)) {
            return true;
        }else{return false;}
    }

    // go les mêmes fonctions pour CRL:
    private boolean crlIsCritical(final X509CRLObject crl, String extensionOid) {
        final Set<String> criticalOids = crl.getCriticalExtensionOIDs();
        if (criticalOids == null || criticalOids.isEmpty()) {
            return false;
        }
        return criticalOids.contains(extensionOid);
    }

    private boolean crlIsExtensionPresent (X509CRLObject crl,String extensionOid) {
        final Set<String>  nonCriticalExtensionOIDs = crl.getNonCriticalExtensionOIDs();
        final Set<String> criticalExtensionOids = crl.getCriticalExtensionOIDs();
        // on cherche parmi les extension critiques et non critiques, et on est censé le trouver.
        if (nonCriticalExtensionOIDs.contains(extensionOid) || criticalExtensionOids.contains(extensionOid)) {
            return true;
        }else{return false;}
    }

    /*
     * go dériver aussi pour  les crl entry extensions
     */
    private boolean crlExtensionisCritical (X509CRLEntry crlEntry, String extensionOid){
        final Set<String> criticalOids = crlEntry.getCriticalExtensionOIDs();
        if (criticalOids == null || criticalOids.isEmpty()) {
            return false;
        }
        return criticalOids.contains(extensionOid);
    }

    private boolean crlExtensionisPresent (X509CRLEntry crlEntry, String extensionOid){
        final Set<String>  nonCriticalExtensionOIDs = crlEntry.getNonCriticalExtensionOIDs();
        final Set<String> criticalExtensionOids = crlEntry.getCriticalExtensionOIDs();
        if (nonCriticalExtensionOIDs.contains(extensionOid) || criticalExtensionOids.contains(extensionOid)) {
            return true;
        }else{return false;}
    }

    /*
     * go éviter de faire la même boucle pour chaque CRL entry extension
     */
    private boolean loopIsAnyCRLExtensionCritical (X509CRLObject crl, String extensionOid){
        Set revokedCert = crl.getRevokedCertificates();
        if (revokedCert!=null){
            Iterator it = revokedCert.iterator();
            while (it.hasNext()){
                X509CRLEntry entry = (X509CRLEntry)it.next();
                if (crlExtensionisCritical(entry,extensionOid)){
                    return true;
                }
            }
        }
        return false;
    }

    /*
     * tableau de comparaison qui vient de code source de la librairie BC
     * permet de choper les noms des algo à partir des oId
     */
    private void fillupOidAlgoNameMap(){
    algorithms.put("MD2WITHRSAENCRYPTION", PKCSObjectIdentifiers.md2WithRSAEncryption.toString());
    algorithms.put("MD2WITHRSA", PKCSObjectIdentifiers.md2WithRSAEncryption.toString());
    algorithms.put("MD5WITHRSAENCRYPTION", PKCSObjectIdentifiers.md5WithRSAEncryption.toString());
    algorithms.put("MD5WITHRSA", PKCSObjectIdentifiers.md5WithRSAEncryption.toString());
    algorithms.put("SHA1WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha1WithRSAEncryption.toString());
    algorithms.put("SHA1WITHRSA", PKCSObjectIdentifiers.sha1WithRSAEncryption.toString());
    algorithms.put("SHA224WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha224WithRSAEncryption.toString());
    algorithms.put("SHA224WITHRSA", PKCSObjectIdentifiers.sha224WithRSAEncryption.toString());
    algorithms.put("SHA256WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha256WithRSAEncryption.toString());
    algorithms.put("SHA256WITHRSA", PKCSObjectIdentifiers.sha256WithRSAEncryption.toString());
    algorithms.put("SHA384WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha384WithRSAEncryption.toString());
    algorithms.put("SHA384WITHRSA", PKCSObjectIdentifiers.sha384WithRSAEncryption.toString());
    algorithms.put("SHA512WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha512WithRSAEncryption.toString());
    algorithms.put("SHA512WITHRSA", PKCSObjectIdentifiers.sha512WithRSAEncryption.toString());
    algorithms.put("SHA1WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS.toString());
    algorithms.put("SHA224WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS.toString());
    algorithms.put("SHA256WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS.toString());
    algorithms.put("SHA384WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS.toString());
    algorithms.put("SHA512WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS.toString());
    algorithms.put("RIPEMD160WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160.toString());
    algorithms.put("RIPEMD160WITHRSA", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160.toString());
    algorithms.put("RIPEMD128WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128.toString());
    algorithms.put("RIPEMD128WITHRSA", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128.toString());
    algorithms.put("RIPEMD256WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256.toString());
    algorithms.put("RIPEMD256WITHRSA", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256.toString());
    algorithms.put("SHA1WITHDSA", X9ObjectIdentifiers.id_dsa_with_sha1.toString());
    algorithms.put("DSAWITHSHA1", X9ObjectIdentifiers.id_dsa_with_sha1.toString());
    algorithms.put("SHA224WITHDSA", NISTObjectIdentifiers.dsa_with_sha224.toString());
    algorithms.put("SHA256WITHDSA", NISTObjectIdentifiers.dsa_with_sha256.toString());
    algorithms.put("SHA384WITHDSA", NISTObjectIdentifiers.dsa_with_sha384.toString());
    algorithms.put("SHA512WITHDSA", NISTObjectIdentifiers.dsa_with_sha512.toString());
    algorithms.put("SHA1WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA1.toString());
    algorithms.put("ECDSAWITHSHA1", X9ObjectIdentifiers.ecdsa_with_SHA1.toString());
    algorithms.put("SHA224WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA224.toString());
    algorithms.put("SHA256WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA256.toString());
    algorithms.put("SHA384WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA384.toString());
    algorithms.put("SHA512WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA512.toString());
    algorithms.put("GOST3411WITHGOST3410", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94.toString());
    algorithms.put("GOST3411WITHGOST3410-94", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94.toString());
    algorithms.put("GOST3411WITHECGOST3410", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001.toString());
    algorithms.put("GOST3411WITHECGOST3410-2001", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001.toString());
    algorithms.put("GOST3411WITHGOST3410-2001", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001.toString());
    algorithms.put("SHA1WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_SHA1.toString());
    algorithms.put("SHA224WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_SHA224.toString());
    algorithms.put("SHA256WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_SHA256.toString());
    algorithms.put("SHA384WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_SHA384.toString());
    algorithms.put("SHA512WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_SHA512.toString());
    algorithms.put("RIPEMD160WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_RIPEMD160.toString());
    algorithms.put("SHA1WITHCVC-ECDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_1.toString());
    algorithms.put("SHA224WITHCVC-ECDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_224.toString());
    algorithms.put("SHA256WITHCVC-ECDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_256.toString());
    algorithms.put("SHA384WITHCVC-ECDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_384.toString());
    algorithms.put("SHA512WITHCVC-ECDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_512.toString());
    algorithms.put("SHA3-512WITHSPHINCS256", BCObjectIdentifiers.sphincs256_with_SHA3_512.toString());
    algorithms.put("SHA512WITHSPHINCS256", BCObjectIdentifiers.sphincs256_with_SHA512.toString());
    }

    private String getKeysByValue (Map algo,String valueToFind){
        if (debug){MainFrame.logger("        starting to search for the right algo name matching the OId: " + valueToFind);}
        Iterator it = algo.entrySet().iterator();
        while (it.hasNext()){
            Map.Entry pair = (Map.Entry)it.next();
            if (Objects.equals(pair.getValue().toString(),valueToFind)){
                if (debug){MainFrame.logger("        found the algo name: " + pair.getKey());}
                return pair.getKey().toString();
            }
            if (debug){MainFrame.logger("          checked:" + pair.getKey() + "->" + pair.getValue() + "....-> NOK");}
        }
        return null;// case where we didn't find anything
    }

    /*
     * check if both collection are equals, without considering the order
     */
    private boolean compareCollection (Collection coll1, Collection coll2) {
        if (coll1.size() != coll2.size()){
            return false;
        }else{
            for (Iterator it = coll1.iterator(); it.hasNext();){
                MainFrame.logger(it.next().getClass().toString());

            }
        }
        return false;
    }

    /*
     * see if needed
     * thanks to http://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java
     */
    public static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for(byte b: a)
            sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    //évitons juste les System.out.print sans le sysout de AchIIIIIIm
    private static void logger1 (String msg,BufferedWriter writer) {
        Date d = new Date(System.currentTimeMillis());
        Calendar calendar = GregorianCalendar.getInstance();
        calendar.setTime(d);
        try {
            System.out.print(System.lineSeparator() + msg);Thread.sleep(1000);
            writer.write(calendar.get(Calendar.DATE)+"/"+calendar.get(Calendar.MONTH)+ " - " + calendar.get(Calendar.HOUR) + ":" + calendar.get(Calendar.MINUTE) + ":" + calendar.get(Calendar.SECOND) + "," + calendar.get(Calendar.MILLISECOND) + " " + msg+"\n");
            writer.newLine();
        } catch (Exception e) {
            System.out.print("ERR: PB écriture");
            System.out.print(e.getMessage());
        }
    }
}
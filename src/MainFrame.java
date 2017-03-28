import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.jce.provider.X509CRLObject;
import org.bouncycastle.jce.provider.X509CertificateObject;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.nio.file.Files;
import java.security.cert.CRLException;
import java.security.cert.CertificateParsingException;
import java.util.Date;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Enumeration;

/**
 * Created by cgorlt on 17/10/2016.
 */
public class MainFrame {

    public static void main (String[] args) {
        try {

            //define the backend constructor
            boolean debug=true;
            BCProvider bc= new BCProvider(debug);

            //define top container
            JFrame frame = new JFrame("ICAO CSCA, DS certificates & CRL verification tool");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

            JPanel panel = new JPanel(new GridBagLayout());
            //panel.setBackground(Color.WHITE);
            GridBagConstraints gbc = new GridBagConstraints();
            //icon: INCERT logo
            ImageIcon logo = new ImageIcon("X:\\Users\\cgorlt\\Documents\\Chirimayo\\src\\ressource\\logo3.PNG");//createLogo("INCERT logo.jpg");
            gbc.anchor = GridBagConstraints.FIRST_LINE_START;
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.gridx = 0;
            gbc.gridy = 0;
            panel.add(new JLabel(logo),gbc);
            //title
            JLabel maintext = new JLabel("    Please select your certificates or CRL in order to verify their conformity with the relevant ICAO technical specifications:       ");// the beginning space are to separate this string from the logo
            //maintext.setBackground(Color.GREEN);
            gbc.anchor = GridBagConstraints.PAGE_START;
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.gridx = 1;
            gbc.gridy = 0;
            panel.add(maintext,gbc);
            //define radio button for kind of a menu
            //first for the cert type
            final ButtonGroup bgType = new ButtonGroup();
            JRadioButton cscaRootButton = new JRadioButton("CSCA Root certificate");
            JRadioButton cscaLinkButton = new JRadioButton("CSCA Link certificate");
            JRadioButton dsButton = new JRadioButton("DS certificate");
            JRadioButton crlButton = new JRadioButton("CRL");
            bgType.add(cscaRootButton);
            bgType.add(cscaLinkButton);
            bgType.add(dsButton);
            bgType.add(crlButton);
            cscaRootButton.setSelected(true);
                //create a underlying layout to order the button in each case
                JPanel internalPanel = new JPanel();
                //internalPanel.setBackground(Color.WHITE);
                internalPanel.setLayout(new BorderLayout());
                internalPanel.setMinimumSize(new Dimension(100,100));//width,height
                internalPanel.setBorder(BorderFactory.createTitledBorder("Select the type of file to verify(DER format):"));
                internalPanel.add(dsButton,BorderLayout.NORTH);
                    //create a second underlying layout to order the new CSCA LINK button ....
                    JPanel internalPanelCSCA = new JPanel();
                    //internalPanelCSCA.setBackground(Color.GRAY);
                    internalPanelCSCA.setLayout(new BorderLayout());
                    internalPanelCSCA.add(cscaRootButton,BorderLayout.NORTH);
                    internalPanelCSCA.add(cscaLinkButton,BorderLayout.CENTER);
                internalPanel.add(internalPanelCSCA,BorderLayout.CENTER);
                internalPanel.add(crlButton,BorderLayout.SOUTH);
            gbc.anchor=GridBagConstraints.LINE_START;
            gbc.ipady = 20;
            gbc.gridx = 0;
            gbc.gridy = 1;
            gbc.weightx = 1;//align the panel with the 3 Radio button on the left side
            panel.add(internalPanel,gbc);

            //then for the BTechVersion
            ButtonGroup bgBTec = new ButtonGroup();
            JRadioButton bTec1Button = new JRadioButton("Doc9303 Edition 6 (before June 2015)");
            JRadioButton bTec2Button = new JRadioButton("Doc9303 Edition 7 (June 2015)");
            bgBTec.add(bTec1Button);
            bgBTec.add(bTec2Button);
            bTec1Button.setSelected(true);
                //create a underlying layout to order the button in each case
                JPanel internalPanel2 = new JPanel();
                //internalPanel2.setBackground(Color.GRAY);
                internalPanel2.setLayout(new BorderLayout());
                internalPanel2.setMinimumSize(new Dimension(80,100));
                internalPanel2.setBorder(BorderFactory.createTitledBorder("ICAO technical specification:"));
                internalPanel2.add(bTec1Button,BorderLayout.NORTH);
                internalPanel2.add(bTec2Button,BorderLayout.CENTER);
            gbc.anchor=GridBagConstraints.LAST_LINE_START;
            gbc.ipady = 0;
            gbc.gridx = 0;
            gbc.gridy = 1;
            gbc.weightx = 1;
            panel.add(internalPanel2,gbc);

            //file chooser to browse file
            final JFileChooser fc = new JFileChooser();
            //fc.setBackground(Color.white);
            gbc.anchor = GridBagConstraints.CENTER;
            gbc.ipady = 40;      //make this component tall
            gbc.gridwidth = 3;
            gbc.gridx = 1;
            gbc.gridy = 1;
            panel.add(fc,gbc);
            //result area
            final JTextArea resultTextArea = new JTextArea();
            resultTextArea.setText("");
            resultTextArea.setEditable(false);
            resultTextArea.setBackground(Color.white);
            gbc.ipady = 50;
            gbc.weighty = 1.0;
            gbc.gridx = 1;
            gbc.gridy = 2;
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.anchor = GridBagConstraints.PAGE_END;
            panel.add(resultTextArea,gbc);

            //define filechooser behavior
            fc.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    if (e.getActionCommand().equalsIgnoreCase("ApproveSelection")) {
                        //first find out which radio button is selected:
                        String certTypeSelected="";
                        Enumeration<AbstractButton> allRadioButton=bgType.getElements();
                        while (allRadioButton.hasMoreElements()) {
                            AbstractButton button = allRadioButton.nextElement();
                            if (button.isSelected()) {
                                certTypeSelected=button.getText();
                            }
                        }
                        String bTecVersionSelected="";
                        Enumeration<AbstractButton> allRadioButton2=bgBTec.getElements();
                        while (allRadioButton2.hasMoreElements()) {
                            AbstractButton button = allRadioButton2.nextElement();
                            if (button.isSelected()) {
                                bTecVersionSelected=button.getText();
                            }
                        }
                        if (certTypeSelected.isEmpty()){logger("WARNING: at least one Radio button has to be selected");System.exit(1);
                        }else {
                            boolean version;
                            if (bTecVersionSelected.contains("1")){
                               version=true;
                            }else {version=false;}
                            String result = verify(bc, fc.getSelectedFile(),version,certTypeSelected);
                            resultTextArea.setEditable(true);
                            if (result.isEmpty()){
                                resultTextArea.setText("Parsing "+certTypeSelected+"..."+System.lineSeparator()+"No failed check");
                            }else {
                                resultTextArea.setText("Parsing "+certTypeSelected+"..."+System.lineSeparator()+"Failed verification:"+System.lineSeparator()+result);
                            }
                            resultTextArea.setEditable(false);
                        }
                    }
                }
            });

            //display
            frame.add(panel);
            frame.setMinimumSize(new Dimension(1075,540));
            frame.setPreferredSize(new Dimension(1075,540));//this size allow visible white result box and the bullet point for document type to be aligned
            frame.pack();
            frame.setVisible(true);

        }
        catch(Exception e) {
            System.out.print(e.getMessage());
        }
    }

    private static String verify (BCProvider bc, File selectedFile, boolean bTecVersion, String type) {
        //verify input before dispatching
        if (selectedFile.exists()&&selectedFile.isFile()&&selectedFile.canRead()){
            X509CertificateObject cert = null;
            X509CRLObject crl = null;
            String result = null;
            try{//first verify the parsing is fine
                if (type.contains("CSCA") || type.contains("DS")) {
                    cert = parseCert(selectedFile);
                }else{ // has to be CRL
                    crl = parseCRL(selectedFile);
                }
                logger("parsing Cert or CRL did not throw errors");
            }catch (IOException ioe){
                logger("ERR: IO error while parsing the provided file, it has to be in DER format:"+System.lineSeparator()+ioe.getMessage());
                //use return instead of system.exit(1) so that we can keep on trying other file, and we can write the feedback in the text box
                return "ERR:error while parsing the provided file, it has to be in DER format";
            }catch (CertificateParsingException cpe){
                logger("ERR: Certificate Parsing error while parsing the provided file, it has to be in DER format:"+System.lineSeparator()+cpe.getMessage());
                //use return instead of system.exit(1) so that we can keep on trying other file, and we can write the feedback in the text box
                return "ERR:error while parsing the provided file, it has to be in DER format";
            }catch (CRLException ce){
                logger("ERR: CRL error while parsing the provided file, it has to be in DER format:"+System.lineSeparator()+ce.getMessage());
                //use return instead of system.exit(1) so that we can keep on trying other file, and we can write the feedback in the text box
                return "ERR:error while parsing the provided file, it has to be in DER format";
            }
            try{//then try to verify the parsed Object (Certificate or CRL)
                if (type.contains("Root")) {
                    result = certificateCSCAVerification(bc, cert, bTecVersion,true);
                }else if (type.contains("Link")){
                    result = certificateCSCAVerification(bc,cert,bTecVersion,false);
                }else if (type.contains("DS")){
                    result = certificateDSVerification(bc,cert,bTecVersion);
                }else{ // has to be CRL
                    result = crlVerification(bc,crl,bTecVersion);
                }
                return result;
            }catch (Exception e){
                logger("ERR: error during verify function:"+System.lineSeparator()+e.getMessage());
                logger("ERR: error during verify function_Details:"+System.lineSeparator()+e.getStackTrace());
                //use return instead of system.exit(1) so that we can keep on trying other file, and we can write the feedback in the text box
                return "ERR: error during verify function";
            }

        }else { logger("ERR: selected file cannot be read or does not exist");return "ERR: selected file cannot be read or does not exist";}
    }

    private static String certificateCSCAVerification (BCProvider bc, X509CertificateObject cert,boolean bTechVersion1,boolean root) {
        String msg="";
        if (root){logger(" ...Check provided certificate against CSCA Root certificates requirements:");}
        else{logger(" ...Check provided certificate against CSCA Link certificates requirements:");}
        try {
            //if (bc.verifCSCAVersion3(cert) && bc.verifCSCAPresenceSerialNumber(cert) && bc.verifCSCA20ByteSerialNumber(cert)
            //        && bc.verifCSCANonNegativeSerialNumber(cert) && bc.verifCSCANonZeroSerialNumber(cert) ){
            logger("checking CSCA Certificate for:"+cert.getSubjectX500Principal().toString());

            if (bc.verifCSCAisVersion3(cert)) {
                logger("OK version 3");
            }else{

                msg = msg+"ERR:CSCA.VER.12:failed to verify certificate version 3"+System.lineSeparator();
                logger("ERR:CSCA.VER.12 failed version 3");
            }
            if(bc.verifCSCASerialisPresent(cert)) {
                logger("OK serial presence");
            }else {msg = msg+"ERR:CSCA.SER.14: failed to verify serial presence"+System.lineSeparator();  logger("ERR:CSCA.SER.14 failed serial presence");}
            if (bc.verifCSCASerialisNotNegative(cert)){
                logger("OK no-negative serial");
            }else{msg = msg+"ERR:CSCA.SER.0: failed to verify no-negative serial"+System.lineSeparator();  logger("ERR:CSCA.SER.0 failed no-negative serial");}
            if (bc.verifCSCASerialisNotZero(cert)){
                logger("OK serial different from zero");
            }else{msg = msg+"WARN:CSCA.SER.0: failed to verify serial different from zero"+System.lineSeparator();  logger("WARN:CSCA.SER.0 failed serial different from zero");}
            //CSCA is not 2's complementencoding
            //CSCA not smallest number of octets representation
            if (bc.verifCSCASerialNumberisNotLongerThan20Bytes(cert)) {
                logger("OK serial is 20bytes");
            }else{msg = msg+"ERR:CSCA.SER.3: failed to verify serial is 20bytes"+System.lineSeparator();  logger("ERR:CSCA.SER.3 failed serial is 20bytes");}
            if (bc.verifCSCASigningAlgorithm(cert)){
                logger("OK Signing algo is allowed");
            }else {
                if (bTechVersion1){msg = msg+"WARN:CSCA.SIG.42-43: ";}else{msg = msg+"ERR:CSCA.SIG.42-43: ";}
                msg = msg+"failed to verify Signing algo is allowed"+System.lineSeparator();
                logger("WARN-ERR:CSCA.SIG.42-43 failed Signing algo is allowed");
            }
            if (!root){//start differentiation if root or link
                if (bc.verifCSCALinkIssuerisPresent(cert)){
                    logger("OK Issuer field is present");
                }else {
                    msg = msg+" ERR:CSCA.ISS.14: failed to verify Issuer is present"+System.lineSeparator();  logger("ERR:CSCA.ISS.14 failed Issuer is present");
                }
                if (bc.verifCSCALinkCountryCodeInIssuerisPresent(cert)){
                    logger("OK Issuer contains country code");
                }else{msg = msg+"ERR:CSCA.ISS.10: failed to verify Issuer contains country code"+System.lineSeparator();  logger("ERR:CSCA.ISS.10 failed Issuer contains country code");}
            }
            if (bc.verifCSCACommonNameInIssuerisPresent(cert)){
                logger("OK Issuer CN is present");
            }else {
                if (bTechVersion1){msg = msg+"WARN:CSCA.ISS.34: ";}else{msg = msg+"ERR:CSCA.ISS.34: ";}
                msg = msg+"failed to verify Issuer CN is present"+System.lineSeparator();  logger("WARN-ERR:CSCA.ISS.34 failed Issuer CN is present");
            }
            //CSCA LINK string encoding other than UTF( or PrintableString
            if (bc.verifCSCAValidityisPresent(cert)){
                logger("OK Validity fields are present");
            }else{msg = msg+"ERR:CSCA.VAL.14: failed to verify Validity fields are present"+System.lineSeparator();  logger("ERR:CSCA.VAL.14failed Validity fields are present");}
            //CSCA Date less the 2050 encoded as GeneralizedTime
            //CSCA Date greater than 2049 encoded as UTCTime
            //CSCA Generalized Time has fractional seconds
            //CSCA UTCTime encoding is wrong
            //CSCA Generalized Time encoding is wrong
            if (bc.verifCSCASubjectisPresent(cert)){
                logger("OK Subject is present");
            }else{msg = msg+"ERR:CSCA.SUB.14: failed to verify Subject is present"+System.lineSeparator();  logger("ERR:CSCA.SUB.14 failed Subject is present");}
            if (bc.verifCSCACountryCodeInSubjectisPresent(cert)){
                logger("OK Subject contains country code");
            }else{msg = msg+"ERR:CSCA.SUB.10: failed to verify Subject contains country code"+System.lineSeparator();  logger("ERR:CSCA.SUB.10 failed Subject contains country code");}
            if (bc.verifCSCACommonNameInSubjectisPresent(cert)){
                logger("OK Subject contains Common Name");
            }else{
                if (bTechVersion1){msg=msg+"WARN:CSCA.SUB.34: ";}else {msg=msg+"ERR:CSCA.SUB.34: ";}
                msg = msg+"failed to verify Subject contains Common Name"+System.lineSeparator();
                logger("WARN-ERR:CSCA.SUB.34failed Subject contains Common Name");
            }
            //CSCA String encoding other than UTF8 or PrintableString
            //CSCA ECDSA key has no explicit curve parameters, or has no co-factor, or is not in uncompressed format
            //CSCA Unique Identifiers Is present
            //CSCA Certificate is not self-signed ERR:CSCA.SVA.66 (same as SKi==AKI ??)
            //CSCA Default values are encoded ERR:CSCA.EXT.22
        //extensions check start here
            if (!root){
                if (bc.verifCSCALinkAKIisPresent(cert)){
                    logger("OK AKI is present");
                }else{msg = msg+"ERR:CSCA.AKI.14: failed to verify AKI is present"+System.lineSeparator();  logger("ERR:CSCA.AKI.14 failed AKI is present");}
            }
            if (root){//difference between verifCSCAAKIisNotCritical and verifCSCALinkAKIisNotCritical, cf BCProvider
                if (bc.verifCSCAAKIisNotCritical(cert)){
                    logger("OK AKI is not critical");
                }else{msg = msg+"ERR:CSCA.AKI.18: failed to verify AKI is not critical"+System.lineSeparator();  logger("ERR:CSCA.AKI.18 failed AKI is not critical");}
            }else{
                if (bc.verifCSCALinkAKIisNotCritical(cert)){
                    logger("OK AKI is not critical");
                }else{msg = msg+"ERR:CSCA.AKI.18: failed to verify AKI is not critical"+System.lineSeparator();  logger("ERR:CSCA.AKI.18 failed AKI is not critical");}
            }
            if (bc.verifCSCAAKIKeyIdentifierisPresent(cert)){
                logger("OK AKI has a key id");
            }else{msg = msg+"ERR:CSCA.AKI.25: failed to verify AKI has a key id"+System.lineSeparator();  logger("ERR:CSCA.AKI.25 failed AKI has a key id");}
            if (root){
                if (bc.verifCSCAAKIKeyIdentifierIsSameAsSKIKeyIdentifier(cert)){
                    logger("OK AKI is different from SKI");
                }else{msg = msg+"ERR:CSCA.AKI.39: failed to verify AKI is different from SKI"+System.lineSeparator();  logger("ERR:CSCA.AKI.39 failed AKI is different from SKI");}
            }
            if (bc.verifCSCASKIisNotCritical(cert)){
                logger("OK AKI is not critical");
            }else{msg = msg+"ERR:CSCA.SKI.18: failed to verify AKI is not critical"+System.lineSeparator();  logger("ERR:CSCA.SKI.18 failed AKI is not critical");}
            if (bc.verifCSCASKIisPresent(cert)) {
                logger("OK SKI is present");
            }else{msg = msg+"ERR:CSCA.SKI.14: failed to verify SKI is present"+System.lineSeparator();  logger("ERR:CSCA.SKI.14 failed SKI is present");}
            if (bc.verifCSCASKIHasKeyIdentifier(cert)){
                logger("OK SKI has key id");
            }else{msg = msg+"ERR:CSCA.SKI.23: failed to verify SKI has key id"+System.lineSeparator();  logger("ERR:CSCA.SKI.23 failed SKI has key id");}
            if (bc.verifCSCAKUisPresent(cert)){
                logger("OK KeyUsage is present");
            }else {msg = msg+"ERR:CSCA.BKU.14: failed to verify KeyUsage is present"+System.lineSeparator();  logger("ERR:CSCA.BKU.14 failed KeyUsage is present");}
            if (bc.verifCSCAKUisOnlyCertAndCrlSign(cert)){
                logger("OK Key Usage is only CertSign and CRLSign");
            }else{msg = msg+"ERR:CSCA.BKU.20: failed to verify Key Usage is only CertSign and CRLSign"+System.lineSeparator();  logger("ERR:CSCA.BKU.20 failed Key Usage is only CertSign and CRLSign");}
            if (bc.verifCSCAKUisCritical(cert)){
                logger("OK Key Usage is critical");
            }else{msg = msg+"ERR:CSCA.BKU.19: failed to verify Key Usage is critical"+System.lineSeparator();  logger("ERR:CSCA.BKU.19 failed Key Usage is critical");}
            if (bc.verifCSCAPKUPisNotCritical(cert)){
                logger("OK Private Key Usage Period field is not critical");
            }else{msg = msg+"ERR:CSCA.PKU.18: failed to verify Private Key Usage Period field is not critical"+System.lineSeparator();  logger("ERR:CSCA.PKU.18 failed Private Key Usage Period field is not critical");}
            if (bc.verifCSCAPKUPisPresentAlongWithNotBeforeAndNotAfter(cert)){
                logger("OK Private Key Usage Period field is present, just as  NotAfter and NotBefore");
            }else{msg = msg+"ERR:CSCA.PKU.17: failed to verify Private Key Usage Period field is present, just as  NotAfter and NotBefore"+System.lineSeparator();  logger("ERR:CSCA.PKU.17 Private Key Usage Period field is present, just as  NotAfter and NotBefore");}
            //CSCA Is not encoded as generalizedTime
            if (bc.verifCSCACertPolicyisNotCritical(cert)){
                logger("OK Certificates Policies field is not present");
            }else {msg = msg+"ERR:CSCA.CEP.18: failed to verify Certificates Policies field is not present"+System.lineSeparator();  logger("ERR:CSCA.CEP.18 failed Certificates Policies field is not present");}
            if (bc.verifCSCAPolicyMappingisNotPresent(cert)){
                logger("OK Policy Mappings field is not present");
            }else {msg = msg+"ERR:CSCA.POM.15: failed to verify Policy Mappings field is not present"+System.lineSeparator();  logger("ERR:CSCA.POM.15 failed Policy Mappings field is not present");}
            if (bc.verifCSCASANisPresent(cert)){
                logger("OK Subject alternative name is present");
            }else{
                if (bTechVersion1){msg=msg+"WARN::CSCA.SAN.14: ";}else{msg=msg+"ERR::CSCA.SAN.14: ";}
                msg = msg+"failed to verify Subject alternative name is present"+System.lineSeparator();
                logger("WARN-ERR::CSCA.SAN.14 failed Subject alternative name is present");
            }
            if (bc.verifCSCASANisNotCritical(cert)){
                logger("OK Subject alternative name is not critical");
            }else{msg = msg+"ERR:CSCA.SAN.18: failed to verify Subject alternative name is not critical"+System.lineSeparator();  logger("ERR:CSCA.SAN.18 failed Subject alternative name is not critical");}
            if (bc.verifCSCAIANisNotCritical(cert)){
                logger("OK Issuer alternative name is not critical");
            }else {msg = msg+"ERR:CSCA.IAN.18: failed to verify Issuer alternative name is not critical"+System.lineSeparator();  logger("ERR:CSCA.IAN.18 failed Issuer alternative name is not critical");}
            if (bc.verifCSCAIANisPresent(cert)){
                logger("OK Issuer alternative name is present");
            }else{
                if (bTechVersion1){msg=msg+"WARN:CSCA.IAN.14: ";}else{msg=msg+"ERR:CSCA.IAN.14: ";}
                msg = msg+"failed to verify Issuer alternative name is present"+System.lineSeparator();
                logger("WARN-ERR:CSCA.IAN.14failed Issuer alternative name is present");}
            if (root) {
                if (bc.verifCSCAIANisSameAsSAN(cert)) {
                    logger("OK Issuer alternative name is same as Subject alternative name ");
                } else {
                    if (bTechVersion1) {
                        msg = msg + "WARN:CSCA.IAN.57: ";
                    } else {
                        msg = msg + "ERR:CSCA.IAN.57: ";
                    }
                    msg = msg + "failed to verify Issuer alternative name is same as Subject Alternative name" + System.lineSeparator();
                    logger("WARN-ERR:CSCA.IAN.57 failed Issuer alternative name is same as Subject alternative name");
                }
            }
            //CSCA ROOT only IAN IS same as SAN-> bc.verifCSCAIANisSameAsSAN(cert)
            if (bc.verifCSCASubjectDirAttributesisNotCritical(cert)){
                logger("OK Subject Directory Attributes is not critical");
            }else {msg = msg+"ERR:CSCA.SDA.15: failed to verify Subject Directory Attributes is not critical"+System.lineSeparator();  logger("ERR:CSCA.SDA.15 failed Subject Directory Attributes is not critical");}
            if (bc.verifCSCABasicConstraintsIsPresent(cert)){
                logger("OK Basic Constraints is present");
            }else{msg = msg+"ERR:CSCA.BAC.14: failed to verify Basic Constraints is present"+System.lineSeparator();  logger("ERR:CSCA.BAC.14 failed Basic Constraints is present");}
            if (bc.verifCSCABasicConstraintsIsCritical(cert)){
                logger("OK Basic Constraints is critical");
            }else{msg = msg+"ERR:CSCA.BAC.19: failed to verify Basic Constraints is critical"+System.lineSeparator();  logger("ERR:CSCA.BAC.19 failed Basic Constraints is critical");}
            //CSCA CA bit is not asserted
            if (bc.verifCSCABasicConstraintsPathLengthIsZero(cert)){
                logger("OK Basic Constraints path length is zero");
            }else{
                if (bTechVersion1){msg=msg+"WARN:CSCA.BAC.25: ";}else{msg=msg+"ERR:CSCA.BAC.25: ";}
                msg = msg+"failed to verify Basic Constraints path length is zero"+System.lineSeparator();
                logger("WARN-ERR:CSCA.BAC.25failed Basic Constraints path length is zero");
            }
            if (bc.verifCSCANAmeConstraintsIsNotPresent(cert)){
                logger("OK Name Constraints field is not present");
            }else{msg = msg+"ERR:CSCA.NAC.15: failed to verify Name Constraints field is not present"+System.lineSeparator();  logger("ERR:CSCA.NAC.15 failed Name Constraints field is not present");}
            if (bc.verifCSCAPolicyConstraintsIsNotPresent(cert)){
                logger("OK Policy Constraints field is not present");
            }else{msg = msg+"ERR:CSCA.POC.15: failed to verify Policy Constraints field is not present"+System.lineSeparator();  logger("ERR:CSCA.POC.15 failed Policy Constraints field is not present");}
            if (bc.verifCSCAEKUIsNotPresent(cert)){
                logger("OK Extended Key USage field is not present");
            }else{msg = msg+"ERR:CSCA.EKU.15: failed to verify Extended Key USage field is not present"+System.lineSeparator();  logger("ERR:CSCA.EKU.15 failed Extended Key USage field is not present");}
            if (bc.verifCSCACDPIsNotCritical(cert)){
                logger("OK CRL Distribution Point field is not critical");
            }else {msg = msg+"ERR:CSCA.CDP.18: failed to verify CRL Distribution Point field is not critical"+System.lineSeparator();  logger("ERR:CSCA.CDP.18 failed CRL Distribution Point field is not critical");}
            if (bc.verifCSCACDPIsPresent(cert)){
                logger("OK CRL Distribution point field is present");
            }else {
                if (bTechVersion1){msg=msg+"WARN:CSCA.CDP.14: ";}else{msg=msg+"ERR:CSCA.CDP.14: ";}
                msg = msg+"failed to verify CRL Distribution point field is present"+System.lineSeparator();
                logger("WARN-ERR:CSCA.CDP.14 failed CRL Distribution point field is present");
            }
            if (bc.verifCSCAInhibitAnyPolicyisNotPresent(cert)){
                logger("OK Inhibit Any Policies field is not present");
            }else {msg = msg+"ERR:CSCA.IAP.15: failed to verify Inhibit Any Policies field is not present"+System.lineSeparator();  logger("ERR:CSCA.IAP.15 failed Inhibit Any Policies field is not present");}
            if (bc.verifCSCAFreshestCRLisNotPresent(cert)) {
                logger("OK Freshest CRL field is not present");
            }else{msg = msg+"ERR:CSCA.FCR.15: failed to verify Freshest CRL field is not present"+System.lineSeparator();  logger("ERR:CSCA.FCR.15 failed Freshest CRL field is not present");}
            if (bc.verifCSCAPrivateInternetExtensionisNotCritical(cert)){
                logger("OK Private internet extensions field is not critical");
            }else{msg = msg+"ERR:CSCA.PIE.18: failed to verify Private internet extensions field is not critical"+System.lineSeparator();  logger("ERR:CSCA.PIE.18 failed Private internet extensions field is not critical");}
            if (bc.verifCSCANetscapeCertExtensionisNotPresent(cert)){
                logger("OK Netscape Certificate extensions field is not present");
            }else{msg = msg+"ERR:CSCA.NCE.15: failed to verify Netscape Certificate extensions field is not present"+System.lineSeparator();  logger("ERR:CSCA.NCE.15 failed Netscape Certificate extensions field is not present");}
        }
        catch (Exception e){
            logger("ERR: certificate verification failed because of :"+System.lineSeparator()+e.getMessage());
        }

        return msg;
    }

    private static String certificateDSVerification (BCProvider bc, X509CertificateObject cert,boolean bTechVersion1) {
        //clearly we are going to re-use the CSCA function if the same verification has to be done
        String msg="";
        logger("checking DS Certificate for:"+cert.getSubjectX500Principal().toString());

        if (bc.verifCSCAisVersion3(cert)) {
            logger("OK version 3");
        }else{
            msg = msg+"ERR:DSC.VER.12:failed to verify certificate version 3"+System.lineSeparator();
            logger("ERR:DSC.VER.12 failed version 3");
        }
        if(bc.verifCSCASerialisPresent(cert)) {
            logger("OK serial presence");
        }else {msg = msg+"ERR:DSC.SER.14: failed to verify serial presence"+System.lineSeparator();  logger("ERR:DSC.SER.14 failed serial presence");}
        if (bc.verifCSCASerialisNotNegative(cert)){
            logger("OK no-negative serial");
        }else{msg = msg+"ERR:DS.SER.0: failed to verify no-negative serial"+System.lineSeparator();  logger("ERR:CSCA.SER.0 failed no-negative serial");}
        if (bc.verifCSCASerialisNotZero(cert)){
            logger("OK serial different from zero");
        }else{msg = msg+"WARN:DSC.SER.0: failed to verify serial different from zero"+System.lineSeparator();  logger("WARN:DSC.SER.0 failed serial different from zero");}

        if (bc.verifCSCASerialNumberisNotLongerThan20Bytes(cert)) {
            logger("OK serial is less than 20bytes");
        }else{msg = msg+"ERR:DSC.SER.3: failed to verify serial is less than 20bytes"+System.lineSeparator();  logger("ERR:DSC.SER.3 failed serial is less than 20bytes");}
        if (bc.verifCSCASigningAlgorithm(cert)){
            logger("OK Signing algo is allowed");
        }else {
            if (bTechVersion1){msg = msg+"WARN:DSC.SIG.42-43: ";}else{msg = msg+"ERR:DSC.SIG.42-43: ";}
            msg = msg+"failed to verify Signing algo is allowed"+System.lineSeparator();
            logger("WARN-ERR:DSC.SIG.42-43 failed Signing algo is allowed");
        }
        if (bc.verifDSissuerisPresent(cert)){
            logger("OK Issuer is present");
        }else{msg = msg+"ERR:DSC.ISS.14: failed to verify Issuer is present"+System.lineSeparator();  logger("ERR:DSC.ISS.14 failed Issuer is present");}
        if (bc.verifDSCountryCodeInIssuerisPresent(cert)){
            logger("OK Issuer Country code is present ");
        }else{
            msg = msg+"ERR:DSC.ISS.10: failed to verify Issuer Country code is present"+System.lineSeparator();
            logger("ERR:DSC.ISS.10 failed Issuer Country code is present");
        }
        if (bc.verifCSCACommonNameInIssuerisPresent(cert)){
            logger("OK Issuer CN is present");
        }else {
            if (bTechVersion1){msg = msg+"WARN:DSC.ISS.34: ";}else{msg = msg+"ERR:DSC.ISS.34: ";}
            msg = msg+"failed to verify Issuer CN is present"+System.lineSeparator();  logger("WARN-ERR:DSC.ISS.34 failed Issuer CN is present");
        }

        if (bc.verifCSCAValidityisPresent(cert)){
            logger("OK Validity fields are present");
        }else{msg = msg+"ERR:DSC.VAL.14: failed to verify Validity fields are present"+System.lineSeparator();  logger("ERR:DSC.VAL.14 failed Validity fields are present");}

        if (bc.verifCSCASubjectisPresent(cert)){
            logger("OK Subject is present");
        }else{msg = msg+"ERR:DSC.SUB.14: failed to verify Subject is present"+System.lineSeparator();  logger("ERR:DSC.SUB.14 failed Subject is present");}
        if (bc.verifCSCACountryCodeInSubjectisPresent(cert)){
            logger("OK Subject contains country code");
        }else{msg = msg+"ERR:DSC.SUB.10: failed to verify Subject contains country code"+System.lineSeparator();  logger("ERR:DSC.SUB.10 failed Subject contains country code");}
        if (bc.verifCSCACommonNameInSubjectisPresent(cert)){
            logger("OK Subject contains Common Name");
        }else{
            if (bTechVersion1){msg=msg+"WARN:DSC.SUB.34: ";}else {msg=msg+"ERR:DSC.SUB.34: ";}
            msg = msg+"failed to verify Subject contains Common Name"+System.lineSeparator();
            logger("WARN-ERR:DSC.SUB.34 failed Subject contains Common Name");
        }

        //extensions check
        if (bc.verifDSAKIIsPresent(cert)){
            logger("OK AKI is present");
        }else {msg = msg+"ERR:DSC.AKI.14: failed to verify AKI is present"+System.lineSeparator();  logger("ERR:DSC.AKI.14 failed AKI is present");}
        if (bc.verifCSCAAKIisNotCritical(cert)){
            logger("OK AKI is not critical");
        }else{msg = msg+"ERR:DSC.AKI.18: failed to verify AKI is not critical"+System.lineSeparator();  logger("ERR:DSC.AKI.18 failed AKI is not critical");}
        if (bc.verifCSCAAKIKeyIdentifierisPresent(cert)){
            logger("OK AKI has a key id");
        }else{msg = msg+"ERR:DSC.AKI.23: failed to verify AKI has a key id"+System.lineSeparator();  logger("ERR:DSC.AKI.23 failed AKI has a key id");}

        if (bc.verifCSCASKIisNotCritical(cert)){
            logger("OK AKI is not critical");
        }else{msg = msg+"ERR:DSC.SKI.18: failed to verify AKI is not critical"+System.lineSeparator();  logger("ERR:DSC.SKI.18 failed AKI is not critical");}
        if (bc.verifCSCAKUisPresent(cert)){
            logger("OK KeyUsage is present");
        }else {msg = msg+"ERR:DSC.BKU.14: failed to verify KeyUsage is present"+System.lineSeparator();  logger("ERR:DSC.BKU.14 failed KeyUsage is present");}
        if (bc.verifDSKUisOnlyDigitalSignature(cert)){
            logger("OK Key Usage is only digital sign");
        }else{msg = msg+"ERR:DSC.BKU.21: failed to verify Key Usage is only digital Sign"+System.lineSeparator();  logger("ERR:DSC.BKU.21 failed Key Usage is only digital Signature");}
        if (bc.verifCSCAKUisCritical(cert)){
            logger("OK Key Usage is critical");
        }else{msg = msg+"ERR:DSC.BKU.19: failed to verify Key Usage is critical"+System.lineSeparator();  logger("ERR:DSC.BKU.19 failed Key Usage is critical");}
        if (bc.verifCSCAPKUPisNotCritical(cert)){
            logger("OK Private Key Usage Period field is not critical");
        }else{msg = msg+"ERR:DSC.PKU.18: failed to verify Private Key Usage Period field is not critical"+System.lineSeparator();  logger("ERR:DSC.PKU.18 failed Private Key Usage Period field is not critical");}
        if (bc.verifCSCAPKUPisPresentAlongWithNotBeforeAndNotAfter(cert)){
            logger("OK Private Key Usage Period field is present, just as  NotAfter and NotBefore");
        }else{msg = msg+"ERR:DSC.PKU.17: failed to verify Private Key Usage Period field is present, just as  NotAfter and NotBefore"+System.lineSeparator();  logger("ERR:DSC.PKU.17 Private Key Usage Period field is present, just as  NotAfter and NotBefore");}

        if (bc.verifCSCACertPolicyisNotCritical(cert)){
            logger("OK Certificates Policies field is not present");
        }else {msg = msg+"ERR:DSC.CEP.18: failed to verify Certificates Policies field is not present"+System.lineSeparator();  logger("ERR:DSC.CEP.18 failed Certificates Policies field is not present");}
        if (bc.verifCSCAPolicyMappingisNotPresent(cert)){
            logger("OK Policy Mappings field is not present");
        }else {msg = msg+"ERR:DSC.POM.15: failed to verify Policy Mappings field is not present"+System.lineSeparator();  logger("ERR:DSC.POM.15 failed Policy Mappings field is not present");}
        if (bc.verifCSCASANisPresent(cert)){
            logger("OK Subject alternative name is present");
        }else{
            if (bTechVersion1){msg=msg+"WARN:DSC.SAN.14: ";}else{msg=msg+"ERR:DSC.SAN.14: ";}
            msg = msg+"failed to verify Subject alternative name is present"+System.lineSeparator();
            logger("WARN-ERR::DSC.SAN.14 failed Subject alternative name is present");
        }
        if (bc.verifCSCASANisNotCritical(cert)){
            logger("OK Subject alternative name is not critical");
        }else{msg = msg+"ERR:DSC.SAN.18: failed to verify Subject alternative name is not critical"+System.lineSeparator();  logger("ERR:DSC.SAN.18 failed Subject alternative name is not critical");}
        if (bc.verifCSCAIANisNotCritical(cert)){
            logger("OK Issuer alternative name is not critical");
        }else {msg = msg+"ERR:DSC.IAN.18: failed to verify Issuer alternative name is not critical"+System.lineSeparator();  logger("ERR:DSC.IAN.18 failed Issuer alternative name is not critical");}
        if (bc.verifCSCAIANisPresent(cert)){
            logger("OK Issuer alternative name is present");
        }else{
            if (bTechVersion1){msg=msg+"WARN:DSC.IAN.14: ";}else{msg=msg+"ERR:DSC.IAN.14: ";}
            msg = msg+"failed to verify Issuer alternative name is present"+System.lineSeparator();
            logger("WARN-ERR:CSCA.IAN.14failed Issuer alternative name is present");}

        if (bc.verifCSCASubjectDirAttributesisNotCritical(cert)){
            logger("OK Subject Directory Attributes is not critical");
        }else {msg = msg+"ERR:DSC.SDA.15: failed to verify Subject Directory Attributes is not critical"+System.lineSeparator();  logger("ERR:DSC.SDA.15 failed Subject Directory Attributes is not critical");}
        if (bc.verifDSBasicConstraintsIsNotPresent(cert)){
            logger("OK Basic Constraints is not present");
        }else{msg = msg+"ERR:DSC.BAC.15: failed to verify Basic Constraints is not present"+System.lineSeparator();  logger("ERR:DSC.BAC.15 failed Basic Constraints is not present");}
        if (bc.verifCSCANAmeConstraintsIsNotPresent(cert)){
            logger("OK Name Constraints field is not present");
        }else{msg = msg+"ERR:DSC.NAC.15: failed to verify Name Constraints field is not present"+System.lineSeparator();  logger("ERR:DSC.NAC.15 failed Name Constraints field is not present");}
        if (bc.verifCSCAPolicyConstraintsIsNotPresent(cert)){
            logger("OK Policy Constraints field is not present");
        }else{msg = msg+"ERR:DSC.POC.15: failed to verify Policy Constraints field is not present"+System.lineSeparator();  logger("ERR:DSC.POC.15 failed Policy Constraints field is not present");}
        if (bc.verifCSCAEKUIsNotPresent(cert)){
            logger("OK Extended Key USage field is not present");
        }else{msg = msg+"ERR:DSC.EKU.15: failed to verify Extended Key USage field is not present"+System.lineSeparator();  logger("ERR:DSC.EKU.15 failed Extended Key USage field is not present");}
        if (bc.verifCSCACDPIsNotCritical(cert)){
            logger("OK CRL Distribution Point field is not critical");
        }else {msg = msg+"ERR:DSC.CDP.18: failed to verify CRL Distribution Point field is not critical"+System.lineSeparator();  logger("ERR:DSC.CDP.18 failed CRL Distribution Point field is not critical");}
        if (bc.verifCSCACDPIsPresent(cert)){
            logger("OK CRL Distribution point field is present");
        }else {
            if (bTechVersion1){msg=msg+"WARN:DSC.CDP.14: ";}else{msg=msg+"ERR:DSC.CDP.14: ";}
            msg = msg+"failed to verify CRL Distribution point field is present"+System.lineSeparator();
            logger("WARN-ERR:DSC.CDP.14 failed CRL Distribution point field is present");
        }
        if (bc.verifCSCAInhibitAnyPolicyisNotPresent(cert)){
            logger("OK Inhibit Any Policies field is not present");
        }else {msg = msg+"ERR:DSC.IAP.15: failed to verify Inhibit Any Policies field is not present"+System.lineSeparator();  logger("ERR:DSC.IAP.15 failed Inhibit Any Policies field is not present");}
        if (bc.verifCSCAFreshestCRLisNotPresent(cert)) {
            logger("OK Freshest CRL field is not present");
        }else{msg = msg+"ERR:DSC.FCR.15: failed to verify Freshest CRL field is not present"+System.lineSeparator();  logger("ERR:DSC.FCR.15 failed Freshest CRL field is not present");}
        if (bc.verifCSCAPrivateInternetExtensionisNotCritical(cert)){
            logger("OK Private internet extensions field is not critical");
        }else{msg = msg+"ERR:DSC.PIE.15: failed to verify Private internet extensions field is not critical"+System.lineSeparator();  logger("ERR:DSC.PIE.15 failed Private internet extensions field is not critical");}
        if (bc.verifCSCANetscapeCertExtensionisNotPresent(cert)){
            logger("OK Netscape Certificate extensions field is not present");
        }else{msg = msg+"ERR:DSC.NCE.15: failed to verify Netscape Certificate extensions field is not present"+System.lineSeparator();  logger("ERR:DSC.NCE.15 failed Netscape Certificate extensions field is not present");}
        if (bc.verifDSDocumentTypeisPresent(cert)){
            logger("OK Document type is present");
        }else{
            if (bTechVersion1){msg=msg+"WARN:DSC.DTL.14: ";}else{msg=msg+"ERR:DSC.DTL.14: ";}
            msg = msg+"failed to verify document type field is present"+System.lineSeparator();
            logger("WARN-ERR:DSC.CTL.14 failed document type field is present");
        }
        return msg;
    }

    private static String crlVerification (BCProvider bc, X509CRLObject crl,boolean bTechVersion1) {
        String msg="";
        logger("checking CRL for:"+ crl.getIssuerX500Principal().toString());
        if (bc.verifCRLisVersion3(crl)) {
            logger("OK version 3");
        }else{
            msg = msg+"ERR:CRL.VER.12:failed to verify CRL version 3"+System.lineSeparator();
            logger("ERR:CRL.VER.12 failed version 3");
        }
        if (bc.verifCRLIssuerisPresent(crl)){
            logger("OK Issuer is present");
        }else {
            msg = msg + "ERR:CRL.ISS.14:failed to verify Issuer field is present" + System.lineSeparator();
            logger("ERR:CRL.ISS.14 failed Issuer is present");
        }
        if (bc.verifCRLCountryCodeInIssuerisPresent(crl)){
            logger("OK Country Code in Issuer is present");
        }else {
            msg = msg + "ERR:CRL.ISS.10:failed to verify country code in Issuer field is present" + System.lineSeparator();
            logger("ERR:CRL.ISS.10 failed country code in Issuer is present");
        }


        if (bc.verifCRLthisUpdateisPresent(crl)){
            logger("OK thisUpdate field is present");
        }else {
            msg = msg + "ERR:CRL.TUP.14:failed to verify thisUpdate field is present" + System.lineSeparator();
            logger("ERR:CRL.TUP.14 failed thisUpdate is present");
        }





        if (bc.verifCRLnextUpdateisPresent(crl)){
            logger("OK nextUpdate is present");
        }else {
            msg = msg + "ERR:CRL.NUP.14:failed to verify nextUpdate field is present" + System.lineSeparator();
            logger("ERR:CRL.NUP.14 failed nextUpdate is present");
        }








        if (bc.verifCRLAKIisPresent(crl)){
            logger("OK AKI is present");
        }else {
            msg = msg + "ERR:CRL.AKI.14:failed to verify AKI field is present" + System.lineSeparator();
            logger("ERR:CRL.AKI.14 failed AKI is present");
        }
        if (bc.verifCRLAKIisNotCritical(crl)){
            logger("OK AKI is critical is present");
        }else {
            msg = msg + "ERR:CRL.AKI.18:failed to verify AKi field is critical" + System.lineSeparator();
            logger("ERR:CRL.AKI.18 failed AKi field is critical");
        }
        if (bc.verifCRLAKIKeyIdentifierisPresent(crl)) {
            logger("OK AKI has Key id");
        }else {
            msg = msg + "ERR:CRL.AKI.23:failed to verify AKi has key ID" + System.lineSeparator();
            logger("ERR:CRL.AKI.23 failed AKi has key ID");
        }
        if (bc.verifCRLIANisNotCritical(crl)) {
            logger("OK AKI has Key id");
        }else {
            msg = msg + "ERR:CRL.IAN.18:failed to verify AKi has key ID" + System.lineSeparator();
            logger("ERR:CRL.IAN.18 failed AKi has key ID");
        }
        if (bc.verifCRLNumberisPresent(crl)){
            logger("OK CRL Number is present");
        }else {
            msg = msg + "ERR:CRL.CRN.18:failed to verify CRL number is present" + System.lineSeparator();
            logger("ERR:CRL.CRN.18 failed CRL number is present");
        }



        if (bc.verifCRLNumberIsNotNegative(crl)){
            logger("OK CRL Number is not negative");
        }else {
            msg = msg + "ERR:CRL.CRN.0:failed to verify CRL Number is not negative" + System.lineSeparator();
            logger("ERR:CRL.CRN.0 failed CRL Number is not negative");
        }
        if (bc.verifCRLnumberIsNotCritical(crl)){
            logger("OK CRL Number is not critical");
        }else {
            msg = msg + "ERR:CRL.CRN.18:failed to verify CRL Number is not critical" + System.lineSeparator();
            logger("ERR:CRL.CRN.18 failed CRL Number is not critical");
        }
        if (bc.verifCRLDeltaIndicatorIsNotPresent(crl)){
            logger("OK CRL Delta indicator is not present");
        }else {
            msg = msg + "ERR:CRL.DCR.15:failed to verify CRL Delta indicator is not present" + System.lineSeparator();
            logger("ERR:CRL.DCR.15 failed CRL Delta indicator is not present");
        }
        if (bc.verifCRLIssuingDPIsNotPresent(crl)){
            logger("OK CRL issuing distribution point is not present");
        }else {
            msg = msg + "ERR:CRL.IDP.15:failed to verify CRL issuing distribution point is not present" + System.lineSeparator();
            logger("ERR:CRL.IDP.15 failed CRL issuing distribution point is not present");
        }
        if (bc.verifCRLFreshestCrlIsNotpresent(crl)){
            logger("OK Freshest CRL field is not present");
        }else {
            msg = msg + "ERR:CRL.FCR.15:failed to verify Freshest CRL field is not present" + System.lineSeparator();
            logger("ERR:CRL.FCR.15 failed Freshest CRL field is not present");
        }
        if (bc.verifCRLEntryReasonCodeIsNotCritical(crl)){
            logger("OK CRL entry extension Reason Code are not critical");
        }else {
            if (bTechVersion1){msg=msg+"WARN:CRL.REA.18: ";}else{msg=msg+"ERR:CRL.REA.18: ";}
            msg = msg+"failed to verify CRL entry extension Reason Code are not critical"+System.lineSeparator();
            logger("WARN-ERR:CRL.REA.18 failed CRL entry extension Reason Code are not critical");
        }
        if (bc.verifCRLEntryHoldInstuctionCodeIsNotCritical(crl)){
            logger("OK CRL entry extension Hold Instruction Code are not critical");
        }else {
            if (bTechVersion1){msg=msg+"WARN:CRL.HIC.18: ";}else{msg=msg+"ERR:CRL.HIC.18: ";}
            msg = msg+"failed to verify CRL entry extension Hold instructions code are not critical"+System.lineSeparator();
            logger("WARN-ERR:CRL.HIC.18 failed CRL entry extension Hold instructions code are not critical");
        }
        if (bc.verifCRLEntryInvalidityDateIsNotCritical(crl)){
            logger("OK CRL Entry extension Invalidity date are not critical");
        }else {
            if (bTechVersion1){msg=msg+"WARN:CRL.IND.18: ";}else{msg=msg+"ERR:CRL.IND.18: ";}
            msg = msg+"failed to verify CRL entry extension Invalidity date are not critical"+System.lineSeparator();
            logger("WARN-ERR:CRL.IND.18 failed CRL entry extension Invalidity date are not critical");
        }

        if (bc.verifCRLEntryCertificateIssuerIsNotPresent(crl)){
            logger("OK CRL Entry extension certificate issuer are not present");
        }else {
            msg = msg+"ERR:CRL.CEI.15: failed to verify CRL entry certificate issuer are not present"+System.lineSeparator();
            logger("ERR:CRL.CEI.15 failed CRL entry extension certificate issuer are not present");
        }
        return msg;
    }

    private static X509CRLObject parseCRL (File file) throws IOException,CRLException{
        //the exception are throws because that way we can catch them in function verify and there the error message can be displayed in the text box
        ASN1InputStream aIn = new ASN1InputStream(Files.readAllBytes(file.toPath()));
        ASN1Sequence crlInfo = (ASN1Sequence)aIn.readObject();
        ASN1Sequence seq = ASN1Sequence.getInstance(crlInfo);
        return new X509CRLObject(CertificateList.getInstance(seq));

    }

    private static X509CertificateObject parseCert (File file) throws IOException,CertificateParsingException{
        //same here: the exception are throws because that way we can catch them in function verify and there the error message can be displayed in the text box
        //logger("parsing  file located in :"+file.getAbsolutePath());
        ASN1InputStream derin = new ASN1InputStream(Files.readAllBytes(file.toPath()));
        ASN1Primitive certInfo = derin.readObject();
        ASN1Sequence seq = ASN1Sequence.getInstance(certInfo);
        return new X509CertificateObject(org.bouncycastle.asn1.x509.Certificate.getInstance(seq));
    }


     public static void logger(String msg){
        Date d =new Date(System.currentTimeMillis());
        Calendar calendar = GregorianCalendar.getInstance();
        calendar.setTime(d);
        File logFile = new File("C:\\Windows\\Temp\\Chirimayo.log");
        try {
            FileWriter fout = new FileWriter(logFile,true);
            System.out.print(System.lineSeparator() + msg);
            BufferedWriter writer = new BufferedWriter(fout);
            writer.write(calendar.get(Calendar.DATE)+"/"+calendar.get(Calendar.MONTH)+ " - " + calendar.get(Calendar.HOUR) + ":" + calendar.get(Calendar.MINUTE) + ":" + calendar.get(Calendar.SECOND) + "," + calendar.get(Calendar.MILLISECOND) + " " + msg+"\n");
            writer.newLine();
            writer.close();
            fout.close();
        }catch (Exception e){
            System.out.print("ERR: PB écriture");
            System.out.print(e.getMessage());
        }
    }
}
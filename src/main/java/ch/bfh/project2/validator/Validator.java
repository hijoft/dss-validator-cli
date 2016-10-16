/*
 * Copyright (C) 2016 Jan Hirsiger jan@hirsiger.org.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301  USA
 */
package ch.bfh.project2.validator;

import ch.bfh.project2.validator.helper.CLIArgs;
import ch.bfh.project2.validator.exception.InitializationException;
import ch.bfh.project2.validator.tslprovider.SQLDatabaseTrustedCertificateSource;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.client.crl.OnlineCRLSource;
import eu.europa.esig.dss.client.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.tsl.ServiceInfo;
import eu.europa.esig.dss.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.x509.crl.CRLSource;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.MissingArgumentException;
import org.apache.commons.cli.MissingOptionException;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.io.FilenameUtils;

public class Validator {

    private static final String REPORT_FORMAT_STANDARD = "std";
    private static final String REPORT_FORMAT_DETAIL = "detail";
    private static final String REPORT_FORMAT_DIAGNOSTIC = "diagnostic";

    private static final String DEFAULTPOLICY = "policy/constraint_original.xml";

    private static final Logger LOGGER = Logger.getLogger(Validator.class.getName());

    public static void main(String args[]) {

        CommandLineParser cliParser = new DefaultParser();

        Options options = new Options();
        options.addOption(CLIArgs.HELP.shortArg(), CLIArgs.HELP.longArg(), false, "Shows this help dialog");
        options.addOption(Option.builder(CLIArgs.FILE.shortArg()).longOpt(CLIArgs.FILE.longArg()).argName("PDF-FILE").hasArg().required().desc("The PDF file to validate. If a directory is provided, the application will search for documents and validate them.").build());
        options.addOption(Option.builder(CLIArgs.CERTS.shortArg()).longOpt(CLIArgs.CERTS.longArg()).argName("DIRECTORY").hasArg().desc("directory containing certificates for validation. If no certificates are provided, no certificate is used for validation.").build());
        options.addOption(Option.builder(CLIArgs.POLICY.shortArg()).longOpt(CLIArgs.POLICY.longArg()).argName("XML-FILE").hasArg().desc("DSS Validation Policy (XML Format). If not defined, the default policy is used.").build());
        options.addOption(Option.builder(CLIArgs.RFORMAT.shortArg()).longOpt(CLIArgs.RFORMAT.longArg()).argName("ATTRIBUTE").hasArg().desc("Report format. Multiple formats must be provided comma-separated without whitespace. Possible attributes: " + REPORT_FORMAT_STANDARD + " (default), " + REPORT_FORMAT_DETAIL + ", " + REPORT_FORMAT_DIAGNOSTIC + ".").build());
        options.addOption(Option.builder(CLIArgs.RDEST.shortArg()).longOpt(CLIArgs.RDEST.longArg()).argName("DIRECTORY").hasArg().desc("Destination for output file. If not defined, the output directory containing the PDF file is used.").build());
        options.addOption(Option.builder(CLIArgs.DB.shortArg()).longOpt(CLIArgs.DB.longArg()).desc("Certificates are loaded from the database specified in db.config.properties").build());

        CommandLine cliCmd;
        try {
            cliCmd = cliParser.parse(options, args);
        } catch (ParseException pe) {
            if (pe instanceof MissingOptionException) {
                LOGGER.log(Level.WARNING, "Missing option: {0}", pe.getMessage());
            } else if (pe instanceof MissingArgumentException) {
                LOGGER.log(Level.WARNING, "Missing argument for option: {0}", pe.getMessage());
            } else {
                LOGGER.log(Level.SEVERE, pe.getMessage());
            }
            new HelpFormatter().printHelp("Validator", options);
            return;
        }
        if (cliCmd.hasOption(CLIArgs.HELP.shortArg())) {
            new HelpFormatter().printHelp("Validator", options);
            return;
        }

        //PDF must be available  
        List<File> pdfFiles = new ArrayList();
        String destinationPath;
        File pdfFile = new File(handleHomePath(cliCmd.getOptionValue(CLIArgs.FILE.shortArg())));
        if (!pdfFile.exists()) {
            LOGGER.log(Level.WARNING, "{0}: PDF file not found: {1}", new Object[]{CLIArgs.FILE.toString(), pdfFile.getPath()});
            return;
        } else if (pdfFile.isDirectory()) {
            LOGGER.log(Level.INFO, "{0}: Directory found. Searching for documents in {1}", new Object[]{CLIArgs.FILE.toString(), pdfFile.getPath()});
            destinationPath = pdfFile.getAbsolutePath();
            buildPDFList(pdfFiles, pdfFile);
        } else {
            destinationPath = new File(pdfFile.getAbsolutePath()).getParent();
            pdfFiles.add(pdfFile);
        }

        //Check report destination directory
        if (cliCmd.hasOption(CLIArgs.RDEST.shortArg())) {
            File destDirectory = new File(handleHomePath(cliCmd.getOptionValue(CLIArgs.RDEST.shortArg())));
            if (destDirectory.exists() && !destDirectory.isDirectory()) {
                LOGGER.log(Level.WARNING, "{0}: No valid directory given as argument: {1}", new Object[]{CLIArgs.RDEST.toString(), destDirectory.getPath()});
                return;
            }
            if (!destDirectory.exists()) {
                try {
                    destDirectory.mkdirs();
                } catch (SecurityException se) {
                    LOGGER.log(Level.SEVERE, "{0}: Cannot create destination directories. {1}", new Object[]{CLIArgs.RDEST.toString(), se.getMessage()});
                    return;
                }
            }
            destinationPath = destDirectory.getPath();
        }

        String defaultPolicy = Validator.class.getClassLoader().getResource(DEFAULTPOLICY).getPath();
        File policyFile = new File(defaultPolicy);
        //Check custom policy
        if (cliCmd.hasOption(CLIArgs.POLICY.shortArg())) {
            policyFile = new File(handleHomePath(cliCmd.getOptionValue(CLIArgs.POLICY.shortArg())));
            if (!policyFile.exists() || policyFile.isDirectory()) {
                LOGGER.log(Level.SEVERE, "{0}: Policy file not found: {1}", new Object[]{CLIArgs.POLICY.toString(), policyFile.getPath()});
                return;            
            }         
        }
        LOGGER.log(Level.INFO, "Using Policy: {0}", policyFile.getPath());

        List<String> reportFormats = new ArrayList();
        //Check report format
        if (cliCmd.hasOption(CLIArgs.RFORMAT.shortArg())) {
            String[] format = cliCmd.getOptionValue(CLIArgs.RFORMAT.shortArg()).split(",");
            for (String f : format) {
                if (f.trim().equalsIgnoreCase(REPORT_FORMAT_STANDARD)
                        || f.trim().equalsIgnoreCase(REPORT_FORMAT_DETAIL)
                        || f.trim().equalsIgnoreCase(REPORT_FORMAT_DIAGNOSTIC)) {
                    reportFormats.add(f.trim().toLowerCase());
                }
            }
            if (reportFormats.isEmpty()) {
                LOGGER.log(Level.WARNING, "{0}: No valid report format given as argument: {1}", new Object[]{CLIArgs.RFORMAT.toString(), format});
                return;
            }
        } else {
            //Add default
            reportFormats.add(REPORT_FORMAT_STANDARD);
        }

        CommonTrustedCertificateSource certSource = null;
        if (cliCmd.hasOption(CLIArgs.DB.shortArg())) {
            try {
                certSource = new SQLDatabaseTrustedCertificateSource();
            } catch (InitializationException ex) {
                LOGGER.log(Level.SEVERE, null, ex);
                return;
            }
        }

        if (certSource == null) {
            certSource = new TrustedListsCertificateSource();
        }
        //Check certs directory
        if (cliCmd.hasOption(CLIArgs.CERTS.shortArg())) {
            File certDirectory = new File(handleHomePath(cliCmd.getOptionValue(CLIArgs.CERTS.shortArg())));
            if (!certDirectory.exists() || !certDirectory.isDirectory()) {
                LOGGER.log(Level.WARNING, "{0}: No valid directory given as argument: {1}", new Object[]{CLIArgs.CERTS.toString(), certDirectory.getPath()});
                return;
            }
            //Load all certificates in folder to trusted cert store
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                buildTrustList(certSource, cf, certDirectory);
            } catch (CertificateException ce) {
                LOGGER.log(Level.SEVERE, ce.getMessage());
                return;
            }
        }
        LOGGER.log(Level.INFO, "Found {0} certificates", certSource.getNumberOfTrustedCertificates());
        LOGGER.log(Level.INFO, "Found {0} files", pdfFiles.size());

        for (File pdf : pdfFiles) {
            //Load pdf
            DSSDocument document = new FileDocument(pdf);

            SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
            CommonCertificateVerifier verifier = new CommonCertificateVerifier();
           
            //Load crl data from urls stored inside the certificates
            CRLSource crlSource = new OnlineCRLSource();
            verifier.setCrlSource(crlSource);
            OCSPSource ocspSource = new OnlineOCSPSource();
            verifier.setOcspSource(ocspSource);

            verifier.setTrustedCertSource(certSource);
            validator.setCertificateVerifier(verifier);

            Reports reports = validator.validateDocument(policyFile);
            try {
                if (reportFormats.contains(REPORT_FORMAT_STANDARD)) {
                    saveReport(new ByteArrayInputStream(reports.getXmlSimpleReport().getBytes("UTF-8")), getReportSavePath(destinationPath, REPORT_FORMAT_STANDARD, policyFile.getName(), pdf.getName()));
                }
                if (reportFormats.contains(REPORT_FORMAT_DETAIL)) {
                    saveReport(new ByteArrayInputStream(reports.getXmlDetailedReport().getBytes("UTF-8")), getReportSavePath(destinationPath, REPORT_FORMAT_DETAIL, policyFile.getName(), pdf.getName()));
                }
                if (reportFormats.contains(REPORT_FORMAT_DIAGNOSTIC)) {
                    saveReport(new ByteArrayInputStream(reports.getXmlDiagnosticData().getBytes("UTF-8")), getReportSavePath(destinationPath, REPORT_FORMAT_DIAGNOSTIC, policyFile.getName(), pdf.getName()));
                }
            } catch (UnsupportedEncodingException ex) {
                    LOGGER.log(Level.SEVERE, null, ex);
            }
        }
        LOGGER.log(Level.INFO, "Finished");
        System.exit(0);
    }

    private static String getReportSavePath(String destinationDirectory, String reportFormat, String policy, String pdfFileName) {
        return destinationDirectory + File.separator + pdfFileName + "_" + policy + "_" + reportFormat + "ValidationReport" + ".xml";
    }
    
    private static String handleHomePath(String path){
        return path.replaceFirst("^~",System.getProperty("user.home"));
    }

    private static void saveReport(InputStream is, String path) {
        try {
            DSSUtils.saveToFile(is, path);
            LOGGER.log(Level.INFO, "Created Report: {0}", path);
        } catch (IOException ex) {
            LOGGER.log(Level.SEVERE, null, ex);
        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (IOException ex) {
                    LOGGER.log(Level.SEVERE, null, ex);
                }
            }
        }
    }

    private static void buildTrustList(CommonTrustedCertificateSource tsl, CertificateFactory cf, File directory) {
        for (File file : directory.listFiles()) {
            if (file.isDirectory()) {
                //Recursive call
                buildTrustList(tsl, cf, directory);
            } else {
                InputStream inStream = null;
                try {
                    X509Certificate x509Cert = (X509Certificate) cf.generateCertificate(new FileInputStream(file.getPath()));
                    tsl.addCertificate(new CertificateToken(x509Cert), new ServiceInfo());
                } catch (CertificateException | FileNotFoundException ce) {
                    LOGGER.log(Level.SEVERE, null, ce);
                } finally {
                    if (inStream != null) {
                        try {
                            inStream.close();
                        } catch (IOException ex) {
                            LOGGER.log(Level.SEVERE, null, ex);
                        }
                    }
                }
            }
        }
    }

    private static void buildPDFList(List<File> pdfList, File directory) {
        for (File file : directory.listFiles()) {
            if (file.isDirectory()) {
                //Recursive call
                buildPDFList(pdfList, directory);
            } else if (file.exists() && FilenameUtils.isExtension(file.getName(), "pdf")) {
                //TODO: check whether it is really a pdf
                pdfList.add(file);
            }
        }
    }

}

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
package ch.bfh.project2.validator.tslprovider;

import ch.bfh.project2.validator.exception.InitializationException;
import eu.europa.esig.dss.tsl.ServiceInfo;
import eu.europa.esig.dss.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.CommonTrustedCertificateSource;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.Blob;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;


public class SQLDatabaseTrustedCertificateSource extends TrustedListsCertificateSource {

    //Regex for raw config options validation.
    private static final String NAMERGX = "[a-zA-Z0-9_]+";

    public SQLDatabaseTrustedCertificateSource() throws InitializationException {

        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException ex) {
            throw new InitializationException(ex.getMessage(), ex);
        }

        //Load configuration from file
        Properties properties = new Properties();
        try {
            InputStream is = getClass().getClassLoader().getResourceAsStream("config/db.config.properties");
            properties.load(is);
        } catch (IOException ex) {
            throw new InitializationException(ex.getMessage(), ex);
        }

        String dbName = properties.getProperty("db");
        String tableName = properties.getProperty("table");
        String blobCol = properties.getProperty("column");
        verifiyProperties(dbName, tableName, blobCol);

        Connection conn = null;
        Statement stmt = null;
        try {
            //Try to load certificates from database            
            conn = DriverManager.getConnection(properties.getProperty("url"), properties.getProperty("username"), properties.getProperty("password"));
            CertificateFactory cf;
            try {
                cf = CertificateFactory.getInstance("X.509");
            } catch (CertificateException ex) {
                throw new InitializationException(ex.getMessage(), ex);
            }

            stmt = conn.createStatement();
            String sql = "SELECT " + blobCol + " FROM " + dbName + "." + tableName;
            ResultSet result = stmt.executeQuery(sql);

            while (result.next()) {
                Blob blob = result.getBlob(blobCol);
                byte[] certData = blob.getBytes(1, 2);
                if (certData[0] == 0x30) {
                    try {
                        //DER Format
                        X509Certificate x509Cert = (X509Certificate) cf.generateCertificate(blob.getBinaryStream());
                        this.addCertificate(new CertificateToken(x509Cert), new ServiceInfo());
                    } catch (CertificateException ex) {
                        throw new InitializationException(ex.getMessage(), ex);
                    }
                }
            }
            
        } catch (SQLException ex) {
            throw new InitializationException(ex.getMessage(), ex);
        } finally {
            try {
                if (stmt != null) {
                    stmt.close();
                }
                if (conn != null) {
                    conn.close();
                }
            } catch (SQLException ex) {
                throw new InitializationException(ex.getMessage(), ex);
            }
        }
    }

    private void verifiyProperties(String dbName, String tableName, String blobCol) throws InitializationException {
        String errors = "";
        boolean nf = false;
        if (!dbName.matches(NAMERGX)) {
            errors += "Database name";
            nf = true;
        }
        if (!tableName.matches(NAMERGX)) {
            if (nf) {
                errors += ", ";
            }
            errors += "Table name";
            nf = true;
        }
        if (!blobCol.matches(NAMERGX)) {
            if (nf) {
                errors += ", ";
            }
            errors += "Column name";
            nf = true;
        }
        if (nf) {
            throw new InitializationException("Error in DB config: " + errors);
        }
    }

}

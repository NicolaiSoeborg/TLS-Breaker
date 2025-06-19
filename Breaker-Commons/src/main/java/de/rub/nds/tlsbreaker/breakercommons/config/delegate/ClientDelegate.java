/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.breakercommons.config.delegate;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.Delegate;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import java.net.*;
import org.bouncycastle.util.IPAddress;

public class ClientDelegate extends Delegate {

    private static final int DEFAULT_HTTPS_PORT = 443;

    @Parameter(names = "-connect", description = "Who to connect to. Syntax: localhost:4433")
    private String host = null;

    @Parameter(names = "-server_name", description = "Server name for the SNI extension.")
    private String sniHostname = null;

    private String extractedHost = null;

    private int extractedPort;

    /**
     * Default constructor for ClientDelegate.
     */
    public ClientDelegate() {}

    /**
     * Returns the configured host connection string.
     *
     * @return the host connection string in format "host:port"
     */
    public String getHost() {
        return host;
    }

    /**
     * Sets the host connection string and extracts host and port parameters.
     *
     * @param host the host connection string in format "host:port"
     */
    public void setHost(String host) {
        this.host = host;
        extractParameters();
    }

    /**
     * Applies this delegate configuration to the provided Config object.
     * Configures the client connection with host, port, and optional SNI hostname.
     *
     * @param config the Config object to apply the delegate settings to
     * @throws com.beust.jcommander.ParameterException if host format is invalid
     */
    @Override
    public void applyDelegate(Config config) {
        extractParameters();

        config.setDefaultRunningMode(RunningModeType.CLIENT);
        OutboundConnection con = config.getDefaultClientConnection();
        if (con == null) {
            con = new OutboundConnection();
            config.setDefaultClientConnection(con);
        }
        con.setPort(extractedPort);
        if (IPAddress.isValid(extractedHost)) {
            con.setIp(extractedHost);
            con.setHostname(extractedHost);
            if (sniHostname != null) {
                con.setHostname(sniHostname);
            }
        } else {
            if (sniHostname != null) {
                con.setHostname(sniHostname);
            } else {
                con.setHostname(extractedHost);
            }
            con.setIp(getIpForHost(extractedHost));
        }
    }

    private void extractParameters() {
        if (host == null) {
            // Though host is a required parameter we can get here if
            // we call applyDelegate manually, e.g. in tests.
            throw new ParameterException("Could not parse provided host: " + host);
        }
        // Remove any provided protocols
        String[] split = host.split("://");
        if (split.length > 0) {
            host = split[split.length - 1];
        }
        host = IDN.toASCII(host);
        URI uri;
        try {
            // Add a dummy protocol
            uri = new URI("my://" + host);
        } catch (URISyntaxException ex) {
            throw new ParameterException("Could not parse host '" + host + "'", ex);
        }
        if (uri.getHost() == null) {
            throw new ParameterException("Provided host seems invalid:" + host);
        }

        if (uri.getPort() <= 0) {
            extractedPort = DEFAULT_HTTPS_PORT;
        } else {
            extractedPort = uri.getPort();
        }
        extractedHost = uri.getHost();
    }

    private String getIpForHost(String host) {
        try {
            InetAddress inetAddress = InetAddress.getByName(host);
            return inetAddress.getHostAddress();
        } catch (UnknownHostException ex) {
            LOGGER.warn("Could not resolve host \"" + host + "\" returning anyways", ex);
            return host;
        }
    }

    private String getHostForIp(String ip) {
        try {
            return InetAddress.getByName(ip).getCanonicalHostName();
        } catch (UnknownHostException ex) {
            LOGGER.warn("Could not perform reverse DNS for \"" + ip + "\"", ex);
            return ip;
        }
    }

    /**
     * Returns the configured SNI hostname.
     *
     * @return the SNI hostname, or null if not set
     */
    public String getSniHostname() {
        return sniHostname;
    }

    /**
     * Sets the SNI hostname for the Server Name Indication extension.
     *
     * @param sniHostname the SNI hostname to use
     */
    public void setSniHostname(String sniHostname) {
        this.sniHostname = sniHostname;
    }

    /**
     * Returns the host extracted from the connection string.
     *
     * @return the extracted host
     */
    public String getExtractedHost() {
        return extractedHost;
    }

    /**
     * Returns the port extracted from the connection string.
     *
     * @return the extracted port number
     */
    public int getExtractedPort() {
        return extractedPort;
    }
}

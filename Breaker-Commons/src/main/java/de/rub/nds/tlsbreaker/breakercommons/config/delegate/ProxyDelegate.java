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

public class ProxyDelegate extends Delegate {

    @Parameter(
            names = {"-proxyData", "-proxy_data"},
            description =
                    "Specify the host and port for data used in the proxy. Syntax: localhost:4444")
    private String proxyData = "localhost:4444";

    @Parameter(
            names = {"-proxyControl", "-proxy_control"},
            description =
                    "Specify the host and port for control messages used in the proxy. Syntax: localhost:5555")
    private String proxyControl = "localhost:5555";

    /**
     * Applies this delegate configuration to the provided Config object.
     * Configures the proxy settings for both data and control connections.
     *
     * @param config the Config object to apply the delegate settings to
     * @throws com.beust.jcommander.ParameterException if proxy data format is invalid
     */
    @Override
    public void applyDelegate(Config config) {

        OutboundConnection con = config.getDefaultClientConnection();
        if (con == null) {
            con = new OutboundConnection();
            config.setDefaultClientConnection(con);
        }
        if (proxyData != null) {
            String[] parsedProxyData = proxyData.split(":");
            switch (parsedProxyData.length) {
                case 1:
                    con.setProxyDataHostname(proxyData);
                    break;
                case 2:
                    con.setProxyDataHostname(parsedProxyData[0]);
                    con.setProxyDataPort(parsePort(parsedProxyData[1]));
                    break;
                default:
                    throw new ParameterException(
                            "Could not parse provided proxyData: " + proxyData);
            }
        }

        if (proxyControl != null) {
            String[] parsedProxyControl = proxyControl.split(":");
            switch (parsedProxyControl.length) {
                case 1:
                    con.setProxyControlHostname(proxyControl);
                    break;
                case 2:
                    con.setProxyControlHostname(parsedProxyControl[0]);
                    con.setProxyControlPort(parsePort(parsedProxyControl[1]));
                    break;
                default:
                    throw new ParameterException(
                            "Could not parse provided proxyControl: " + proxyControl);
            }
        }
    }

    private int parsePort(String portStr) {
        int port = Integer.parseInt(portStr);
        if (port < 0 || port > 65535) {
            throw new ParameterException("port must be in interval [0,65535], but is " + port);
        }
        return port;
    }

    /**
     * Sets the proxy data connection string.
     *
     * @param proxyData the proxy data connection string in format "host:port"
     */
    public void setProxyData(String proxyData) {
        this.proxyData = proxyData;
    }

    /**
     * Sets the proxy control connection string.
     *
     * @param proxyControl the proxy control connection string in format "host:port"
     */
    public void setProxyControl(String proxyControl) {
        this.proxyControl = proxyControl;
    }
}

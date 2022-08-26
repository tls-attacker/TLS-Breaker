/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.poodle.util;

import java.io.IOException;
import java.io.OutputStream;

import org.apache.commons.lang.StringEscapeUtils;

import com.sun.net.httpserver.*;

public class MyHttpHandler implements HttpHandler {

    public boolean decrypted = false;

    @Override
    public void handle(HttpExchange httpExchange) throws IOException {

        String requestParamValue = null;

        if ("GET".equals(httpExchange.getRequestMethod())) {

            requestParamValue = handleGetRequest(httpExchange);

        } else {
            // Do nothing
        }

        handleResponse(httpExchange, requestParamValue);

    }

    private String handleGetRequest(HttpExchange httpExchange) {

        return httpExchange.

            getRequestURI()

            .toString()

            .split("\\?")[1]

                .split("=")[1];

    }

    private void handleResponse(HttpExchange httpExchange, String requestParamValue) throws IOException {

        OutputStream outputStream = httpExchange.getResponseBody();

        // encode HTML content

        String htmlResponse = "" + decrypted;

        // this line is a must

        httpExchange.sendResponseHeaders(200, htmlResponse.length());

        outputStream.write(htmlResponse.getBytes());

        outputStream.flush();

        outputStream.close();

    }
}
/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.poodle.util;

import com.sun.net.httpserver.*;
import java.io.IOException;
import java.io.OutputStream;

public class MyHttpHandler implements HttpHandler {

    public boolean decryptionComplete = false;

    public boolean bytedecrypted = false;

    public boolean paddingfound = false;

    public int paddingSize = 0;

    public boolean block_decrypted = false;

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

        return httpExchange.getRequestURI().toString();
    }

    private void handleResponse(HttpExchange httpExchange, String requestParamValue)
            throws IOException {

        OutputStream outputStream = httpExchange.getResponseBody();

        String stringResponse = "";

        String path = httpExchange.getRequestURI().getPath();

        if (path.equals("/paddingfound")) {
            stringResponse += paddingfound;
        } else if (path.equals("/paddingsize")) {
            stringResponse += paddingSize;
        } else if (path.equals("/bytedecrypted")) {
            stringResponse += bytedecrypted;
        } else if (path.equals("/gotonextbyte")) {
            bytedecrypted = false;
        } else if (path.equals("/blockdecrypted")) {
            stringResponse += block_decrypted;
        } else if (path.equals("/gotonextblock")) {
            block_decrypted = false;
        } else if (path.equals("/decryptioncomplete")) {
            stringResponse += decryptionComplete;
        } else {

        }

        // this line is a must

        httpExchange.sendResponseHeaders(200, stringResponse.length());

        outputStream.write(stringResponse.getBytes());

        outputStream.flush();

        outputStream.close();
    }
}

package de.rub.nds.tlsbreaker.poodle.util;

import com.sun.net.httpserver.*;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

public class PoodleHTTPServer {

    private MyHttpHandler httphandler;

    public PoodleHTTPServer(MyHttpHandler httphandler){
        this.httphandler = httphandler;
    }

    

    public void startPoddleHTTPServer() {



        HttpServer server = null;
        try {
            server = HttpServer.create(new InetSocketAddress("localhost", 8001), 0);
        } catch (IOException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }
        
        ThreadPoolExecutor threadPoolExecutor = (ThreadPoolExecutor) Executors.newFixedThreadPool(10);
        server.createContext("/padding", httphandler);
        server.createContext("/byte", httphandler);
        server.createContext("/gotonextbyte", httphandler);
        server.createContext("/decryptioncomplete", httphandler);

        server.setExecutor(threadPoolExecutor);
        server.start();

    }
}

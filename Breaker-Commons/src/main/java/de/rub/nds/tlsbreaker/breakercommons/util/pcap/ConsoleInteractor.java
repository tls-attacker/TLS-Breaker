/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.breakercommons.util.pcap;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.vandermeer.asciitable.AT_Row;
import de.vandermeer.asciitable.AsciiTable;
import de.vandermeer.asciitable.CWC_LongestLine;
import de.vandermeer.skb.interfaces.transformers.textformat.TextAlignment;

import java.util.List;
import java.util.Map;
import java.util.Scanner;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
import static org.apache.commons.lang3.StringUtils.trim;

public class ConsoleInteractor {

    public void displayServerAndSessionCount(List<String> uniqueServers,
                                             Map<String, List<PcapSession>> serverSessionsMap) {
        AsciiTable table = new AsciiTable();
        table.addRule();
        table.addRow("Server Number", "Host Address", "Session Count");
        table.addRule();

        for (int i = 0; i < uniqueServers.size(); i++) {
            String hostAddress = uniqueServers.get(i);
            int numberOfSessions = serverSessionsMap.get(hostAddress).size();
            AT_Row row = table.addRow(i + 1, hostAddress, numberOfSessions);
            setServerTableTextAlignment(row);
        }
        table.addRule();
        formatTable(table);
        System.out.println(table.render());
    }

    public void displayServers(List<String> uniqueServers) {
        AsciiTable table = new AsciiTable();
        table.addRule();
        table.addRow("Server Number", "Host Address");
        table.addRule();

        for (int i = 0; i < uniqueServers.size(); i++) {
            String hostAddress = uniqueServers.get(i);
            AT_Row row = table.addRow(i + 1, hostAddress);
            row.getCells().get(0).getContext().setTextAlignment(TextAlignment.RIGHT);
        }
        table.addRule();
        formatTable(table);
        System.out.println(table.render());
    }

    public void displayServerAndPmsCount(List<String> uniqueServers, Map<String, List<PcapSession>> serverSessionsMap) {
        AsciiTable table = new AsciiTable();
        table.addRule();
        table.addRow("Server Number", "Host Address", "Encrypted Premaster Secret Count");
        table.addRule();

        for (int i = 0; i < uniqueServers.size(); i++) {
            String hostAddress = uniqueServers.get(i);
            int numberOfSessions = serverSessionsMap.get(hostAddress).size();
            AT_Row row = table.addRow(i + 1, hostAddress, numberOfSessions);
            setServerTableTextAlignment(row);
        }
        table.addRule();
        formatTable(table);
        System.out.println(table.render());
    }

    private void setServerTableTextAlignment(AT_Row row) {
        row.getCells().get(0).getContext().setTextAlignment(TextAlignment.RIGHT);
        row.getCells().get(2).getContext().setTextAlignment(TextAlignment.RIGHT);
    }

    public void displaySessionDetails(List<PcapSession> sessions) {
        AsciiTable table = new AsciiTable();
        table.addRule();
        table.addRow("Session Number", "Source", "Cipher Suite", "Protocol Version", "Application data size (kB)");
        table.addRule();

        for (int i = 0; i < sessions.size(); i++) {
            PcapSession session = sessions.get(i);
            ServerHelloMessage serverHellomessage = session.getServerHellomessage();
            CipherSuite selectedCipherSuite =
                    CipherSuite.getCipherSuite(serverHellomessage.getSelectedCipherSuite().getValue());
            ProtocolVersion protocolVersion =
                    ProtocolVersion.getProtocolVersion(serverHellomessage.getProtocolVersion().getValue());
            AT_Row row = table.addRow(i + 1, session.getSourceHost(), selectedCipherSuite, protocolVersion,
                                      session.getApplicationDataSize() / 1000.0);
            setSessionTableTextAlignment(row);
        }
        table.addRule();
        formatTable(table);
        System.out.println(table.render());

    }

    private void setSessionTableTextAlignment(AT_Row row) {
        row.getCells().get(0).getContext().setTextAlignment(TextAlignment.RIGHT);
        row.getCells().get(4).getContext().setTextAlignment(TextAlignment.RIGHT);
    }

    public PcapSession getUserSelectedSession(List<PcapSession> hostSessions) {
        Scanner sc = new Scanner(System.in);
        if (hostSessions.size() == 1) {
            CONSOLE.info("Do you want to execute the attack? (y/n):");
            String userInput = trim(sc.nextLine());
            if ("Y".equals(userInput) || "y".equals(userInput)) {
                return hostSessions.get(0);
            } else if ("N".equals(userInput) || "n".equals(userInput)) {
                CONSOLE.info("Execution of the attack cancelled.");
                return null;
            } else {
                throw new UnsupportedOperationException();
            }
        } else if (hostSessions.size() > 1) {
            CONSOLE.info("Please select a session number to execute an attack.");
            CONSOLE.info("Session Number: ");
            try {
                int sessionNumber = sc.nextInt();
                if (sessionNumber > 0 && sessionNumber <= hostSessions.size()) {
                    return hostSessions.get(sessionNumber - 1);
                } else {
                    throw new UnsupportedOperationException();
                }
            } catch (Exception e) {
                throw new UnsupportedOperationException();
            }
        } else {
            CONSOLE.error("Error!");
            return null;
        }
    }

    public String getUserDecisionForOneServer() {
        Scanner sc = new Scanner(System.in);
        String userInput = trim(sc.nextLine());
        if ("Y".equals(userInput) || "y".equals(userInput)) {
            int serverNumber = 1;
            return Integer.toString(serverNumber);
        } else if ("N".equals(userInput) || "n".equals(userInput)) {
            return "N";
        } else {
            throw new UnsupportedOperationException();
        }
    }

    public String getUserInputForMultipleServers(List<String> uniqueServers) {
        Scanner sc = new Scanner(System.in);
        try {
            if (sc.hasNextInt()) {
                int serverNumber = sc.nextInt();
                if (isValidNumberSelected(serverNumber, uniqueServers)) {
                    return Integer.toString(serverNumber);
                } else {
                    throw new UnsupportedOperationException();
                }
            } else {
                String userOption = sc.nextLine();
                if ("a".equals(userOption)) {
                    return userOption;
                } else if (isCommaSeparatedInputValid(userOption, uniqueServers)) {
                    return userOption;
                } else {
                    throw new UnsupportedOperationException();
                }
            }
        } catch (Exception e) {
            throw new UnsupportedOperationException();
        }
    }

    private boolean isCommaSeparatedInputValid(String userOption, List<String> uniqueServers) {
        String[] serverNumbers = userOption.split(",");
        for (String serverNumber : serverNumbers) {
            int server = Integer.parseInt(trim(serverNumber));
            if (!isValidNumberSelected(server, uniqueServers)) {
                return false;
            }
        }
        return true;
    }

    private boolean isValidNumberSelected(int number, List<String> list) {
        return number > 0 && number <= list.size();
    }

    private void formatTable(AsciiTable table) {
        // table.setTextAlignment(TextAlignment.CENTER);
        CWC_LongestLine cwc = new CWC_LongestLine();
        cwc.add(10, 0);
        table.getRenderer().setCWC(cwc);
    }

    public String getValidUserSelection(List<String> uniqueServers) {
        if (uniqueServers.size() == 1) {
            CONSOLE.info("Do you want to check the vulnerability of the server? (y/n):");
            return getUserDecisionForOneServer();
        } else {
            CONSOLE.info("Please select server numbers to check for vulnerability "
                                 + "or press 'a' to check for vulnerability of all the servers.");
            CONSOLE.info("Select Option: ");
            return getUserInputForMultipleServers(uniqueServers);
        }
    }

    public int getUserSelectedServer(List<String> uniqueServers) {
        Scanner sc = new Scanner(System.in);
        try {
            int serverNumber = sc.nextInt();
            if (serverNumber > 0 && serverNumber <= uniqueServers.size()) {
                return serverNumber;
            } else {
                throw new UnsupportedOperationException();
            }

        } catch (Exception e) {
            throw new UnsupportedOperationException();
        }
    }

    public String getUserYesNoResponse() {
        Scanner sc = new Scanner(System.in);
        String userInput = trim(sc.nextLine());
        if ("Y".equals(userInput) || "y".equals(userInput)) {
            return "Y";
        } else if ("N".equals(userInput) || "n".equals(userInput)) {
            return "N";
        } else {
            throw new UnsupportedOperationException();
        }
    }
}

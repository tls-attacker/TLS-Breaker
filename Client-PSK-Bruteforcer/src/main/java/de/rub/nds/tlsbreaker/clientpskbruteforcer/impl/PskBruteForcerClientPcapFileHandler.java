/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.clientpskbruteforcer.impl;

import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsbreaker.breakercommons.impl.Attacker;
import de.rub.nds.tlsbreaker.breakercommons.util.file.FileUtils;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.*;
import de.rub.nds.tlsbreaker.clientpskbruteforcer.config.PskBruteForcerAttackClientCommandConfig;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;
import java.util.concurrent.TimeUnit;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
import de.rub.nds.tlsbreaker.breakercommons.psk.GuessProviderType;

public class PskBruteForcerClientPcapFileHandler {

    private static final Logger LOGGER = LogManager.getLogger();
    PskBruteForcerAttackClientCommandConfig pskBruteForcerAttackClientCommandConfig;

    public PskBruteForcerClientPcapFileHandler(
        PskBruteForcerAttackClientCommandConfig pskBruteForcerAttackClientCommandConfig) {
        this.pskBruteForcerAttackClientCommandConfig = pskBruteForcerAttackClientCommandConfig;
    }

    public void handlePcapFile() {
        PcapAnalyzer pcapAnalyzer = new PcapAnalyzer(pskBruteForcerAttackClientCommandConfig.getPcapFileLocation());
        List<PcapSession> sessions = pcapAnalyzer.getAllSessions();

        if (!sessions.isEmpty()) {
            ClientSelection PskBruteForcerClientSelection = new PskBruteForcerClientSelection(sessions);
            ServerSelection pskBruteForcerServerSelection = new PskBruteForcerServerSelection(sessions);

            Map<String, List<PcapSession>> clientSessionsMap = PskBruteForcerClientSelection.getClientSessionsMap();

            Map<String, List<PcapSession>> serverSessionsMap = pskBruteForcerServerSelection.getServerSessionsMap();

            List<String> uniqueClient = new ArrayList<>(clientSessionsMap.keySet());

            List<String> clientServers = new ArrayList<>(serverSessionsMap.keySet());

            // Display the server list and ask for the user to provide the desired input.
            if (!uniqueClient.isEmpty()) {
                CONSOLE.info("Found " + uniqueClient.size() + " Client from the pcap file.");
                ConsoleInteractor consoleInteractor = new ConsoleInteractor();
                consoleInteractor.displayClientWithServers(clientServers, uniqueClient);

                String userOption = consoleInteractor.getValidUserSelectionForPSKClient(uniqueClient);
                if ("N".equals(userOption)) {
                    CONSOLE.info("Execution of the attack cancelled.");
                } else if ("a".equals(userOption)) {
                    throw new UnsupportedOperationException("Invalid option selected!");
                } else if (isCommaSeparatedList(userOption)) {
                    throw new UnsupportedOperationException("Invalid option selected!");
                } else {
                    String host = clientServers.get(Integer.parseInt(userOption) - 1);
                    String source = uniqueClient.get(Integer.parseInt(userOption) - 1);
                    String[] complete_host = host.split(":");
                    int port = Integer.parseInt(complete_host[1]);

                    LOGGER.info("Selected Client: " + source);
                    LOGGER.info("Server PORT: " + port);

                    pskBruteForcerAttackClientCommandConfig.getServerDelegate().setPort(port);
                    pskBruteForcerAttackClientCommandConfig.setSkipConnectionCheck(true);

                    Boolean vulnerability = checkVulnerability(pskBruteForcerAttackClientCommandConfig);
                    if (Objects.equals(vulnerability, Boolean.TRUE)) {
                        CONSOLE.info("Client " + source + " is vulnerable.");
                        CONSOLE.info("Do you want to execute the attack? (y/n):");
                        String userResponse = consoleInteractor.getUserYesNoResponse();
                        if ("Y".equals(userResponse)) {

                            select_attack_method(consoleInteractor);
                            executeAttack(host, pskBruteForcerAttackClientCommandConfig);

                        } else if ("N".equals(userResponse)) {
                            CONSOLE.info("Execution of the attack cancelled.");
                        }
                    } else if (Objects.equals(vulnerability, Boolean.FALSE)) {
                        CONSOLE.info("Client " + source + " is not vulnerable.");
                    } else {
                        CONSOLE.warn("Client " + source + " is not vulnerable.");
                    }
                }
            } else {
                CONSOLE.info("\nFound no potential client for Psk Brute Force Attack.");
            }
        } else {
            CONSOLE.info("No TLS handshake message found.");
        }
    }

    private void checkVulnerabilityOfAllServersAndDisplay(List<String> uniqueClient,
        PskBruteForcerAttackClientCommandConfig pskBruteForcerAttackClientCommandConfig,
        ConsoleInteractor consoleInteractor) {
        List<String> vulnerableServers = getVulnerableServers(uniqueClient, pskBruteForcerAttackClientCommandConfig);

        CONSOLE.info("Found " + vulnerableServers.size() + "  vulnerable Client.");
        if (!vulnerableServers.isEmpty()) {
            consoleInteractor.displayClients(vulnerableServers);

        } else {
            CONSOLE.info("Try checking the client one by one from the list");
        }
        if (vulnerableServers.size() == 1) {

            CONSOLE.info("Do you want to execute the attack? (y/n):");
            String userResponse = consoleInteractor.getUserYesNoResponse();
            if ("Y".equals(userResponse)) {
                select_attack_method(consoleInteractor);
                String host = vulnerableServers.get(0);
                select_attack_method(consoleInteractor);
                executeAttack(host, pskBruteForcerAttackClientCommandConfig);

            } else if ("N".equals(userResponse)) {
                CONSOLE.info("Execution of the attack cancelled.");
            }
        }

        else if (vulnerableServers.size() > 1) {
            CONSOLE.info("Please select a Client number to execute an attack.");
            CONSOLE.info("Client number: ");
            int serverNumber = consoleInteractor.getUserSelectedServer(uniqueClient);
            String host = uniqueClient.get(serverNumber - 1);
            select_attack_method(consoleInteractor);
            executeAttack(host, pskBruteForcerAttackClientCommandConfig);

        }

    }

    private List<String> getVulnerableServers(List<String> uniqueClient,
        PskBruteForcerAttackClientCommandConfig pskBruteForcerAttackClientCommandConfig) {

        List<String> vulnerableServers = new ArrayList<>();
        for (String server : uniqueClient) {

            String host = server;
            String[] complete_host = host.split(":");
            int port = Integer.parseInt(complete_host[1]);
            LOGGER.info("Selected Client: " + host);
            LOGGER.info("Selected Client port: " + port);
            pskBruteForcerAttackClientCommandConfig.getServerDelegate().setPort(port);

            Attacker<? extends TLSDelegateConfig> attacker = new PskBruteForcerAttackClient(
                pskBruteForcerAttackClientCommandConfig, pskBruteForcerAttackClientCommandConfig.createConfig());

            try {
                Boolean result = attacker.checkVulnerability();
                if (Objects.equals(result, Boolean.TRUE)) {
                    CONSOLE.error("Vulnerable:" + result.toString());
                    vulnerableServers.add(server);
                } else if (Objects.equals(result, Boolean.FALSE)) {
                    CONSOLE.info("Vulnerable:" + result.toString());
                } else {
                    CONSOLE.info("Client is not active!!");
                }
            } catch (UnsupportedOperationException e) {
                LOGGER.info("The selected attacker is currently not implemented");
            }
        }
        return vulnerableServers;
    }

    private void executeAttack(String host,
        PskBruteForcerAttackClientCommandConfig pskBruteForcerAttackClientCommandConfig) {

        Attacker<? extends TLSDelegateConfig> attacker = new PskBruteForcerAttackClient(
            pskBruteForcerAttackClientCommandConfig, pskBruteForcerAttackClientCommandConfig.createConfig());
        attacker.attack();
    }

    private boolean isCommaSeparatedList(String userOption) {
        return userOption.contains(",");
    }

    private Boolean
        checkVulnerability(PskBruteForcerAttackClientCommandConfig pskBruteForcerAttackClientCommandConfig) {
        Attacker<? extends TLSDelegateConfig> attacker = new PskBruteForcerAttackClient(
            pskBruteForcerAttackClientCommandConfig, pskBruteForcerAttackClientCommandConfig.createConfig());
        Boolean result = null;
        try {
            TimeUnit.SECONDS.sleep(2);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        try {
            result = attacker.checkVulnerability();
            if (Objects.equals(result, Boolean.TRUE)) {
                CONSOLE.error("Vulnerable:" + result.toString());
            } else if (Objects.equals(result, Boolean.FALSE)) {
                CONSOLE.info("Vulnerable:" + result.toString());
            }

            else {
                CONSOLE.warn("Vulnerable: Uncertain");

            }
        } catch (UnsupportedOperationException e) {
            LOGGER.info("The selected attacker is currently not implemented");
        }
        return result;
    }

    // Method is specific to the PSK_SERVER_Bruteforcer attack. Provide different option to the user
    // to select. Based on the selected option different attack methods are executed.
    private void select_attack_method(ConsoleInteractor consoleInteractor) {
        CONSOLE.info("What type of attack method do you prefer:");
        CONSOLE.info("A: BRUTEFORCER    B: WORDLIST");
        String userchoiceforattack = consoleInteractor.getUserchoiceforpsk();
        if ("B".equals(userchoiceforattack)) {
            CONSOLE.info("You have selected wordlist");
            pskBruteForcerAttackClientCommandConfig.setGuessProviderType(GuessProviderType.WORDLIST);
            CONSOLE.info("Select the preferred wordlist type:");
            CONSOLE.info("A: DEFAULT FILE    B: PERSONAL FILE");
            String userchoiceforfile = consoleInteractor.getUserchoiceforpsk();
            if ("B".equals(userchoiceforfile)) {
                String userprovidedfilepath = consoleInteractor.getUserfilepathinput();
                if (FileUtils.isFileExists(userprovidedfilepath)) {
                    try {
                        pskBruteForcerAttackClientCommandConfig.setGuessProviderInputFile(userprovidedfilepath);
                        CONSOLE.info("WordList file location provided = "
                            + pskBruteForcerAttackClientCommandConfig.getGuessProviderInputFile());
                    } catch (UnsupportedOperationException e) {
                        CONSOLE.error("Invalid option selected! Please run the jar file again.");
                    }
                } else {
                    CONSOLE.error("Invalid File Path! Please enter the Correct file path");
                }

            } else {
                CONSOLE.info("You have selected Default file: Started executing attack based on default wordlist");
            }
        } else {

            CONSOLE.info("You have selected Bruteforce");
            CONSOLE.info("Starting INCREMENTAL Approach");
            pskBruteForcerAttackClientCommandConfig.setGuessProviderType(GuessProviderType.INCREMENTING);
            CONSOLE.info(pskBruteForcerAttackClientCommandConfig.getGuessProviderType());
            pskBruteForcerAttackClientCommandConfig.setGuessProviderInputFile(null);

        }

    }

}

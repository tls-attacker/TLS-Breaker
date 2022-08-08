/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.serverpskbruteforce.impl;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsbreaker.breakercommons.config.delegate.GeneralAttackDelegate;
import de.rub.nds.tlsbreaker.breakercommons.impl.Attacker;
import de.rub.nds.tlsbreaker.breakercommons.util.file.FileUtils;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.ConsoleInteractor;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapAnalyzer;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapSession;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.ServerSelection;
import de.rub.nds.tlsbreaker.serverpskbruteforce.bruteforce.GuessProviderType;
import de.rub.nds.tlsbreaker.serverpskbruteforce.config.PskBruteForcerAttackServerCommandConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.stringtemplate.v4.ST;

import java.util.*;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
import static org.apache.commons.lang3.StringUtils.trim;

public class PskBruteForcerPcapFileHandler {

    private static final Logger LOGGER = LogManager.getLogger();
    PskBruteForcerAttackServerCommandConfig pskBruteForcerAttackServerCommandConfig;

    public PskBruteForcerPcapFileHandler(
        PskBruteForcerAttackServerCommandConfig pskBruteForcerAttackServerCommandConfig) {
        this.pskBruteForcerAttackServerCommandConfig = pskBruteForcerAttackServerCommandConfig;
    }

    public void handlePcapFile() {
        PcapAnalyzer pcapAnalyzer = new PcapAnalyzer(pskBruteForcerAttackServerCommandConfig.getPcapFileLocation());
        List<PcapSession> sessions = pcapAnalyzer.getAllSessions();

        if (!sessions.isEmpty()) {
            ServerSelection pskBruteForcerServerSelection = new PskBruteForcerServerSelection(sessions);
            Map<String, List<PcapSession>> serverSessionsMap = pskBruteForcerServerSelection.getServerSessionsMap();
            List<String> uniqueServers = new ArrayList<>(serverSessionsMap.keySet());
            // Display the server list and ask for the user to provide the desired input.
            if (!uniqueServers.isEmpty()) {
                CONSOLE.info("Found " + uniqueServers.size() + " servers from the pcap file.");
                ConsoleInteractor consoleInteractor = new ConsoleInteractor();
                consoleInteractor.displayServers(uniqueServers);
                String userOption = consoleInteractor.getValidUserSelection(uniqueServers);
                if ("N".equals(userOption)) {
                    CONSOLE.info("Execution of the attack cancelled.");
                } else if ("a".equals(userOption)) {
                    checkVulnerabilityOfAllServersAndDisplay(uniqueServers, pskBruteForcerAttackServerCommandConfig,
                        consoleInteractor);
                } else if (isCommaSeparatedList(userOption)) {
                    List<String> hosts = new ArrayList<>();
                    Arrays.stream(userOption.split(",")).forEach(
                        serverNumber -> hosts.add(uniqueServers.get(Integer.parseInt(trim(serverNumber)) - 1)));

                    checkVulnerabilityOfAllServersAndDisplay(hosts, pskBruteForcerAttackServerCommandConfig,
                        consoleInteractor);
                } else {
                    String host = uniqueServers.get(Integer.parseInt(userOption) - 1);
                    LOGGER.info("Selected server: " + host);
                    pskBruteForcerAttackServerCommandConfig.getClientDelegate().setHost(host);
                    Boolean vulnerability = checkVulnerability(pskBruteForcerAttackServerCommandConfig);
                    if (Objects.equals(vulnerability, Boolean.TRUE)) {
                        CONSOLE.info("Server " + host + " is vulnerable.");
                        CONSOLE.info("Do you want to execute the attack? (y/n):");
                        String userResponse = consoleInteractor.getUserYesNoResponse();
                        if ("Y".equals(userResponse)) {

                            select_attack_method(consoleInteractor);
                            executeAttack(host, pskBruteForcerAttackServerCommandConfig);

                        } else if ("N".equals(userResponse)) {
                            CONSOLE.info("Execution of the attack cancelled.");
                        }
                    } else {
                        CONSOLE.info("The server " + host + " is not vulnerable.");
                    }
                }
            } else {
                CONSOLE.info("\nFound no potential servers for Psk Brute Force Attack.");
            }
        } else {
            CONSOLE.info("No TLS handshake message found.");
        }
    }

    private void checkVulnerabilityOfAllServersAndDisplay(List<String> uniqueServers,
        PskBruteForcerAttackServerCommandConfig pskBruteForcerAttackServerCommandConfig,
        ConsoleInteractor consoleInteractor) {
        List<String> vulnerableServers = getVulnerableServers(uniqueServers, pskBruteForcerAttackServerCommandConfig);

        CONSOLE.info("Found " + vulnerableServers.size() + "  vulnerable server.");
        if (!vulnerableServers.isEmpty()) {
            consoleInteractor.displayServers(vulnerableServers);
        }
        if (vulnerableServers.size() == 1) {

            CONSOLE.info("Do you want to execute the attack? (y/n):");
            String userResponse = consoleInteractor.getUserYesNoResponse();
            if ("Y".equals(userResponse)) {
                select_attack_method(consoleInteractor);
                String host = vulnerableServers.get(0);
                select_attack_method(consoleInteractor);
                executeAttack(host, pskBruteForcerAttackServerCommandConfig);

            } else if ("N".equals(userResponse)) {
                CONSOLE.info("Execution of the attack cancelled.");
            }
        }

        else if (vulnerableServers.size() > 1) {
            CONSOLE.info("Please select a server number to execute an attack.");
            CONSOLE.info("server number: ");
            int serverNumber = consoleInteractor.getUserSelectedServer(uniqueServers);
            String host = uniqueServers.get(serverNumber - 1);
            select_attack_method(consoleInteractor);
            executeAttack(host, pskBruteForcerAttackServerCommandConfig);

        }

    }

    private List<String> getVulnerableServers(List<String> uniqueServers,
        PskBruteForcerAttackServerCommandConfig pskBruteForcerAttackServerCommandConfig) {

        List<String> vulnerableServers = new ArrayList<>();
        for (String server : uniqueServers) {
            pskBruteForcerAttackServerCommandConfig.getClientDelegate().setHost(server);

            Attacker<? extends TLSDelegateConfig> attacker = new PskBruteForcerAttackServer(
                pskBruteForcerAttackServerCommandConfig, pskBruteForcerAttackServerCommandConfig.createConfig());

            try {
                Boolean result = attacker.checkVulnerability();
                if (Objects.equals(result, Boolean.TRUE)) {
                    CONSOLE.error("Vulnerable:" + result.toString());
                    vulnerableServers.add(server);
                }
            } catch (UnsupportedOperationException e) {
                LOGGER.info("The selected attacker is currently not implemented");
            }
        }
        return vulnerableServers;
    }

    private void executeAttack(String host,
        PskBruteForcerAttackServerCommandConfig pskBruteForcerAttackServerCommandConfig) {

        pskBruteForcerAttackServerCommandConfig.getClientDelegate().setHost(host);
        LOGGER.info("host=" + pskBruteForcerAttackServerCommandConfig.getClientDelegate().getHost());

        Attacker<? extends TLSDelegateConfig> attacker = new PskBruteForcerAttackServer(
            pskBruteForcerAttackServerCommandConfig, pskBruteForcerAttackServerCommandConfig.createConfig());
        attacker.attack();
    }

    private boolean isCommaSeparatedList(String userOption) {
        return userOption.contains(",");
    }

    private Boolean
        checkVulnerability(PskBruteForcerAttackServerCommandConfig pskBruteForcerAttackServerCommandConfig) {
        Attacker<? extends TLSDelegateConfig> attacker = new PskBruteForcerAttackServer(
            pskBruteForcerAttackServerCommandConfig, pskBruteForcerAttackServerCommandConfig.createConfig());
        Boolean result = null;
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
            CONSOLE.info("U have selected Wordlist");
            pskBruteForcerAttackServerCommandConfig.setGuessProviderType(GuessProviderType.WORDLIST);
            CONSOLE.info(pskBruteForcerAttackServerCommandConfig.getGuessProviderType());
            CONSOLE.info("Select the preferred wordlist type:");
            CONSOLE.info("A: DEFAULT FILE    B: PERSONAL FILE");
            String userchoiceforfile = consoleInteractor.getUserchoiceforpsk();
            if ("B".equals(userchoiceforfile)) {
                String userprovidedfilepath = consoleInteractor.getUserfilepathinput();
                if (FileUtils.isFileExists(userprovidedfilepath)) {
                    try {
                        pskBruteForcerAttackServerCommandConfig.setGuessProviderInputFile(userprovidedfilepath);
                        CONSOLE.info("WordList file location provided = "
                            + pskBruteForcerAttackServerCommandConfig.getGuessProviderInputFile());
                    } catch (UnsupportedOperationException e) {
                        CONSOLE.error("Invalid option selected! Please run the jar file again.");
                    }
                } else {
                    CONSOLE.error("Invalid File Path! Please enter the Correct file path");
                }

            } else {
                CONSOLE.info("You have selected Default file option: Started executing attack based on default wordlist");
            }
        } else {

            CONSOLE.info("You have selected Bruteforce option.");
            CONSOLE.info("Starting INCREMENTAL Approach");
            pskBruteForcerAttackServerCommandConfig.setGuessProviderType(GuessProviderType.INCREMENTING);
            CONSOLE.info(pskBruteForcerAttackServerCommandConfig.getGuessProviderType());
            pskBruteForcerAttackServerCommandConfig.setGuessProviderInputFile(null);

        }

    }

    // Method to filter out the tls_rsa server from the filtered server which are vulnarable to PSK_Bruteforcer attack

    private List<PcapSession> FindTlsserver(List<PcapSession> sessions) {
        List<PcapSession> filteredRsaServers = new ArrayList<>();
        for (PcapSession s : sessions) {
            ServerHelloMessage shm = s.getServerHellomessage();
            ProtocolVersion selectedProtocol = ProtocolVersion.getProtocolVersion(shm.getProtocolVersion().getValue());
            CipherSuite selectedCipher = CipherSuite.getCipherSuite(shm.getSelectedCipherSuite().getValue());
            if ((selectedCipher.name().contains("TLS_RSA_PSK_")) && !selectedProtocol.name().contains("TLS13")) {
                filteredRsaServers.add(s);
            }
        }
        return filteredRsaServers;
    }

}

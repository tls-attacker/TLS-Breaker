/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.invalidcurve.ec;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import java.io.File;
import java.util.Arrays;
import java.util.List;
import static org.junit.Assert.assertTrue;

/*
 * THIS TEST CHECKS THE PRESENCE OF POINTS FILE, DELETION OF PARTICULAR POINT FILE LEADS TO EXECUTION FAILURE OF THAT
 * PARTICULAR CURVE ATTACK.
 */

public class CheckPointsFile {
    private File FileLocation;
    List<String> pointsFileList = Arrays.asList("points_secp112r1.txt", "points_secp112r2.txt", "points_secp128r1.txt",
        "points_secp128r2.txt", "points_secp160k1.txt", "points_secp160r1.txt", "points_secp160r1.txt",
        "points_secp192k1.txt", "points_secp192r1.txt", "points_secp224k1.txt", "points_secp224r1.txt",
        "points_secp256r1.txt", "points_secp384r1.txt", "points_secp521r1.txt", "points_brainpoolp256r1.txt",
        "points_brainpoolp384r1.txt", "points_brainpoolp512r1.txt");

    public CheckPointsFile() {
        FileLocation = new File("src" + File.separator + "main" + File.separator + "resources" + File.separator);
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Test
    public void testCurvePointsFileExist() {

        for (int i = 0; i < pointsFileList.size(); i++) {
            String filePath = FileLocation.getPath() + File.separator + pointsFileList.get(i);
            File tempFile = new File(filePath);
            boolean exists = tempFile.exists();
            assertTrue("Points File: " + pointsFileList.get(i) + " Missing", exists);

        }

    }
}

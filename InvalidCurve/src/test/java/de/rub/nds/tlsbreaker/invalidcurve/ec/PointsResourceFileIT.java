/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.invalidcurve.ec;

import de.rub.nds.tlsattacker.util.tests.TestCategories;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;

/*
 * THIS TEST CHECKS THE PRESENCE OF POINTS FILE, DELETION OF PARTICULAR POINT FILE LEADS TO EXECUTION FAILURE OF THAT
 * PARTICULAR CURVE ATTACK.
 */

public class PointsResourceFileIT {

    private final List<String> pointsFileList = Arrays.asList();

    public static Stream<Arguments> provideCurvePointsFileList() {
        return Stream.of("points_secp112r1.txt", "points_secp112r2.txt", "points_secp128r1.txt", "points_secp128r2.txt",
            "points_secp160k1.txt", "points_secp160r1.txt", "points_secp160r1.txt", "points_secp192k1.txt",
            "points_secp192r1.txt", "points_secp224k1.txt", "points_secp224r1.txt", "points_secp256r1.txt",
            "points_secp384r1.txt", "points_secp521r1.txt", "points_brainpoolp256r1.txt", "points_brainpoolp384r1.txt",
            "points_brainpoolp512r1.txt").map(Arguments::of);
    }

    @ParameterizedTest
    @MethodSource("provideCurvePointsFileList")
    @Tag(TestCategories.INTEGRATION_TEST)
    public void testCurvePointsFileExist(String providedFileName) {
        File curvePointsFile = new File(String.format("src/main/resources/%s", providedFileName));
        assertTrue(curvePointsFile.exists(), "Curve points file missing: " + curvePointsFile.getAbsolutePath());
    }
}

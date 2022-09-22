/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.breakercommons.util.pcap;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

public class PcapAnalyzerTest {

    public List<PcapSession> fetchSessions(String pcapFile) {
        PcapAnalyzer sample = new PcapAnalyzer(String.format("src/test/resources/pcap_files/%s", pcapFile));
        return sample.getAllSessions();
    }

    public static Stream<Arguments> providePremasterSecretExtractionTestVectors() {
        return Stream.of(Arguments.of("Sample1.pcapng", List.of(ArrayConverter.hexStringToByteArray(
            "60ca0832ac2eb6130b3d695e4e1308f6241b5cbd7e57d3530ff311ebffd47910d67d7f835a6ce8ad859f51cd0f07e794acd6c133f35f67e9b7e18b3f3c67c793d1bb9fd865d661e32317f3f1e95e480998218b9bb09ff90bc2482c32c6e2e4905545980d35b565fecdfd06b1861fb641d151b823abc11e917c5f73d2daeb7231"))),
            Arguments.of("Sample2.pcapng", List.of(ArrayConverter.hexStringToByteArray(
                "63f094976db528b0fac4a130ffea435a098a036f1697700b16e2f795e86b4f5ff614175235e5e8cfc6d97253506a39c7069ac315d5f005ac6f9ee9274f2f5909deb11c567698565b485d63409104e6e3b0ac608355fa5fd91f925614b243bc647f1a7c54322cd16072a574d1fb585d7db84516e5d9e5b80d8870ffccea2c7bf986c99d70c3c5e8da98c07da96587a86711ca2604f2679e81e9c1513a346aecb288b687cc80f62e70991899de704a5570d609bd70edcdeb7e66155274db2df1002813a1927d2c244c68415b215aa257a0e99139ecfa38cdbaa28a026dcbdfdd0b4df3d0a6328b25cf750dc98d665c2b18e6f16a61c5e1f097e6395faa69c61a6a"))),
            // TODO: The following test vectors are broken (missing algorithms?)
            /*
             * Arguments.of("Sample3.pcap", List.of( ArrayConverter.hexStringToByteArray(
             * "707eb01ca5981df78cbe2a44f5c667039d2c35d77db180c89857c534c8ad8b775c6427403bd863e50e9218c10c12e4e22b244089bd6fe0ae19806c20f9ba246a346b147e9351ccbe4b93048cef2e1af6f5a27b02fdf8ddd50cd9de6eecee8378bd45de724f06ffa22fea6c0ff53cbc10321f0ade472f7a689735f80ad432ff20"
             * ), ArrayConverter.hexStringToByteArray(
             * "20ebbf46d49c0dc18b4fc26dce50ce5a6c5ce7ecc79fa236546476da91571625d10b5e9e14a5ffdbac37e1bdf8461d13811dfa72ebb65ce1d754c80307ba2fd492435504b341e7cce1ce724e611ef297372dc9fa7ff7178d361f8bcdbe485292d1bb7847756c54c2e28c8780838b9d10d1b9c8f8445411ff539507d3bb271a2a"
             * ), ArrayConverter.hexStringToByteArray(
             * "60514d9424f0c47db8e45a779cd4ef5f9008560199be8266332d1e365e8782f9b0c3bc18d7c28320ebce0fd84226a401f8754cabb0fc6ae4a664d345176f80d06deb9f31e69e0fbacb7c84eed93fc0ff48b3e7e97092028f9e99a79696854f73d0aa43108dcd9d941275274c1417ef52496eebab76075ff443bd3ce44bab1dff"
             * ))), Arguments.of("Sample4.pcap", List.of(
             * "72ed66df9070c98033961401a194357f95a54d1bcafb51c25717afa960d4517b19299adb3c22f2cec10f9f9eb7475b6e738790d088eea878317f5e9c0d29e441c820623be9dda8a4b5e83fe7b07fa70268b1306c1041d80d13ac7484345376149e590e9cdabf27a6076ce4614c01f7b732c19c2775ac159bc58ff94fc36a8b4a"
             * ))), Arguments.of("Sample5.pcap", List.of( ArrayConverter.hexStringToByteArray(
             * "10941c855a14140cc84657f9fb1f23e37de4ac009b9334f4050bdd9488285d71faf3246f9af6001c1e25c7a9b2ee91d2e9ebda8b4960f3441c2aceca525221e899e8aa94b90b592130111cb94400a05c385da1fa0782e112cae09efe90220fe6d12d0c43b13d04787163dc62573fac53a7d85b6998922d0d99b0c038c8e83cd99dc5fafd686ff29c4796ae610c37a953c3f3898b5b866d69f04624af594e2a1ae2638f361538117465c4d5caac4dc0061011a7924f333363c1cafce5a944e29fbfbe62658e9292712313316bbe8829551186be5a9f94290b831b15c26753f22888ed5d93c4b09199f3de85fcf3e54951fda59a4477bf2e5e9abf338cce1fd92b"
             * ), ArrayConverter.hexStringToByteArray(
             * "ab74132984c60dd25e9dcfc94011e3800a84950e3f846cc23d22c5ea47897e8558a9e42b786955071ed744aaa187e8f6d9d9a7077302fbc107bf48e66ab43a46f05d832617f1d0825a6c1d0ee8b6ea31ba4ea41579d8a6a644e2722f31d2f0262a38788069401db92b733b2d085bd905e8280a4879ed0e3d5f6c3e6d3f37660c33cf59a2ef5e77cc9e999d86477176ae60133002f5b19d8094c8dd59449d9454c253d708acb3515b6e62d0c63cfa1aac4a7503d9b7adb2f18a16c3e1b41ad556bafeebbee1b67357d9c4b252939f6227b61945ef9c216515bc9b2a6f3fe1e8e9500cc99c80a62d3e24cc81bfb808b1445dbf658ef84b468f8d283cdb44370496"
             * ))),
             */
            Arguments.of("2nd_TLS_RSA_PSK_AES.pcapng", List.of(ArrayConverter.hexStringToByteArray(
                "8ed4198be5099c96ac923d54300717dc24814cc2aa0405556084f2d6ce4e48935db7461a74f319768686182afdbbc819c0c222643f1adc492f889f3627bea1affb523a1574eb778cbc985808074a9b8fe7f09705b1fbb9159e7a64e26c99859a69c5a9a36c02961ff1ba68363ade466ba1ed4413d10767d960dc577fd88e20df1fbacc46694d2b36c8683f96703561d779a1d329bb2c51b804097a45602eebdef79f8ce17aa1867b6f10a83b609a9efe0eec0d169d1b827b1990583bd97dcc390e5356fb0f6c27b784656716320eae45ef4cebb99d030a7e10053e96f58c8128a6aa19ceb7de70c249485ba9fd75ee91637485c99bc5a895900e594950641025"))),
            Arguments.of("DH_RSA.pcapng", List.of(ArrayConverter.hexStringToByteArray(
                "63865c3198da9c1eb3836e5b4f395bf95f3897c5035aab70ed300f3fdc904fc66aa7b9a1d023c34f0053432b9871d5aff2d7f4231ce186bda754604b2e664c5762ef81f557506bb35d16522864d67c2c1b014ba44fb2b93155a167ba75c1bed38084e2025db424a39f46e09a576ce1c6b6e938cf68e2277597e0890b00c9626e0260fdfc08df0950d9302402c04afd3dea08ccc69c8877562a5d60d21caab20893a9977b15326a96a3f4e641e5ab77c69309e30d0f7cdb568e7e1d179c28679185edf566aff4973ef167f04fb769695769e503236361042a856dc2988e5b64a2dfd048e28aebb6ad153b1512cb4a5c03a8a8d949248fb74882896ebf430d299ebeff912a3558329cfbf553b5f1fd3d3da7138eb293a4929035da2305913645eb68305d9e1ea49f33af352f02d38133d4873766b07d287dd0221f4a8dd40ca5661e99edb67500e3b92e82bc2666ec9c61071427371817c0253468558df0e808660a6c4a9fef4e1e81c6288b6e6f3d48ca2c81e3c8155cfe89a1d9d3566ef2ebfc"))),
            Arguments.of("TLS_SRP_SHA_RSA_DIFF.pcapng", List.of(new byte[] { 0x20 })),
            Arguments.of("2nd_TLS_RSA_WITH_ARIA.pcapng", List.of(ArrayConverter.hexStringToByteArray(
                "8ed4198be5099c96ac923d54300717dc24814cc2aa0405556084f2d6ce4e48935db7461a74f319768686182afdbbc819c0c222643f1adc492f889f3627bea1affb523a1574eb778cbc985808074a9b8fe7f09705b1fbb9159e7a64e26c99859a69c5a9a36c02961ff1ba68363ade466ba1ed4413d10767d960dc577fd88e20df1fbacc46694d2b36c8683f96703561d779a1d329bb2c51b804097a45602eebdef79f8ce17aa1867b6f10a83b609a9efe0eec0d169d1b827b1990583bd97dcc390e5356fb0f6c27b784656716320eae45ef4cebb99d030a7e10053e96f58c8128a6aa19ceb7de70c249485ba9fd75ee91637485c99bc5a895900e594950641025"))),
            Arguments.of("TLS_ECDH_RSA_WITH_NULL_SHA.pcapng", List.of(ArrayConverter.hexStringToByteArray(
                "045ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032"))),
            Arguments.of("SSLV3_pcap.pcap", List.of(ArrayConverter.hexStringToByteArray(
                "00b46a85398faaa065a43002f0d552fb3f5d5869e55aef98247765009d2e6ed8bdd373f335f3b6634bf882e1c289d58984f6a400941e31fb4a6bf1111c014bdf74843e07a274f7a326c02e24180c67bb3626b38ccc04fc1084332c83e8892d999b30032c4c7a9c2afbe6931d9b572d59503af1491f85287d8f975ed7ec6d4280"),
                ArrayConverter.hexStringToByteArray(
                    "9c5dfc0170b128ec206bf3a1d3ddbb64d6145801e71a4c1738c6b78530dbfc16130460db7ffb42a903efa1859fd98584001ac4ac36f9daf869a5878321037382f20b05dfdea1fad919c867158164a04a5553c2fb676e7755c50f850b0323faf94a4856b0c9099ee161ba8461dce8bcf804f23a6fc61a46f9ce788b99e74a82b1"),
                ArrayConverter.hexStringToByteArray(
                    "9c5dfc0170b128ec206bf3a1d3ddbb64d6145801e71a4c1738c6b78530dbfc16130460db7ffb42a903efa1859fd98584001ac4ac36f9daf869a5878321037382f20b05dfdea1fad919c867158164a04a5553c2fb676e7755c50f850b0323faf94a4856b0c9099ee161ba8461dce8bcf804f23a6fc61a46f9ce788b99e74a82b1"),
                ArrayConverter.hexStringToByteArray(
                    "32f9b5f3f2bfbda93df5a8d49dc0fe10277e8f8c922b6d1b092f4aeb1aaed15935cc54802e48416fae44817c05ca52fd6e23b2e35ff62dedf6beb58cd1260e5a4c9c155dbcd4a61d4a2a249ce703d6cf444707df1cffe0afac7496e25efc401c0906eb0ee7b9eb93d09fe99dc82e7775274f0e4dd5cea6d34063fd9cf13a4598"),
                ArrayConverter.hexStringToByteArray(
                    "00b46a85398faaa065a43002f0d552fb3f5d5869e55aef98247765009d2e6ed8bdd373f335f3b6634bf882e1c289d58984f6a400941e31fb4a6bf1111c014bdf74843e07a274f7a326c02e24180c67bb3626b38ccc04fc1084332c83e8892d999b30032c4c7a9c2afbe6931d9b572d59503af1491f85287d8f975ed7ec6d4280"),
                ArrayConverter.hexStringToByteArray(
                    "32f9b5f3f2bfbda93df5a8d49dc0fe10277e8f8c922b6d1b092f4aeb1aaed15935cc54802e48416fae44817c05ca52fd6e23b2e35ff62dedf6beb58cd1260e5a4c9c155dbcd4a61d4a2a249ce703d6cf444707df1cffe0afac7496e25efc401c0906eb0ee7b9eb93d09fe99dc82e7775274f0e4dd5cea6d34063fd9cf13a4598"))),
            Arguments.of("TLS_RSA_WITH_AES_128_CCM_8.pcapng", List.of(ArrayConverter.hexStringToByteArray(
                "964c569dc5a76281f5cc3e06943790124e9657e909725715596b7dae61af0b97897e568baa1cc140c3345e3027216a5916289c8b83b0e67541fb62e84839bdde07769507706c37680f39e6fd484a241607a9a7441af1dbf873bf7dc122da9bcdd1efdea48dfc3b67cd0e6bc40c9981d2775cbc8f559373140738b930e4c98d928a562d283556dc7ef8666fadaf1a721e8dfb36c40f390bb364d55263bb5b026d3809c5ad5be24d89cbf9e5df10e5b1f37758168cb103f2f86982c0c5dae931c8b5129db8ee83e712e8efd7a02d1a1c847463fc1ebe99891b8cd43a5e2cb7b6b9d633eab43e66267600eecfca9d0675bdb2056425cbe8013abb7e53dd5a7fd3cb"),
                ArrayConverter.hexStringToByteArray(
                    "66eedcf297f82122d280c190a754556c97652307116ffed16b17b585df51c93190c25f03fb9d85cd0d04beee2517d4641bf7733f5d50fe0dbf1f33fd53371eb933e32a645caab6c17b9f28aecc13b81226146272571ca6c9cf9faa12d2cdf42dbec19ae6aff7b7ca99144848fb8c44fe2172ac11bdd1f05c49bd86d4d9e25201cec51d565cdf6958a0d1941de8e692e01effd10c9ebe538fdace68145c5fa57a0529a57612ec76cf5c08f828148d833e68c31ffa0477fdc748638feecbd8ab55dfa2923ea3132338984bb3e543c5c515b4c961cf6e0f1a4305e46523d8c6121fa9e964327e83e87290f001089e965dc9395da0a9f4a844a673ba0e473caab590"),
                ArrayConverter.hexStringToByteArray(
                    "04136b37105afb806709431c6aec699733b7d49d1387183a639a85e62796e608feb2b4f4ccf5946deb1cb21c32a02a3d153c9a8d14a5b271b4c7e26b11987221c61a2ea5bc1afd27d334876b496da4d17a0095e4aed7ab0d8f4ce233d918f6c09d6e4c1cf32de73c70524ebafa78ab893423c6402c84d255a21effc0b3afb7b3549a0862c0a2f31a49f533466316c0d666b03ef08da58f4b232fccc5695840ad6485fe98c819a92ab545bc1c10ecb3592fafe4b24f580307b4d5791fb54d4392da2929be3361748ddba340de42abd1b161d118901d6895fd39d4f92e58b81a46b84409b958e0200d8e7b7db53097dbb15f88ebca3e6300dd116459f888ca877b"),
                ArrayConverter.hexStringToByteArray(
                    "8ed4198be5099c96ac923d54300717dc24814cc2aa0405556084f2d6ce4e48935db7461a74f319768686182afdbbc819c0c222643f1adc492f889f3627bea1affb523a1574eb778cbc985808074a9b8fe7f09705b1fbb9159e7a64e26c99859a69c5a9a36c02961ff1ba68363ade466ba1ed4413d10767d960dc577fd88e20df1fbacc46694d2b36c8683f96703561d779a1d329bb2c51b804097a45602eebdef79f8ce17aa1867b6f10a83b609a9efe0eec0d169d1b827b1990583bd97dcc390e5356fb0f6c27b784656716320eae45ef4cebb99d030a7e10053e96f58c8128a6aa19ceb7de70c249485ba9fd75ee91637485c99bc5a895900e594950641025"))),
            Arguments.of("Mix_file.pcapng", List.of(ArrayConverter.hexStringToByteArray(
                "63865c3198da9c1eb3836e5b4f395bf95f3897c5035aab70ed300f3fdc904fc66aa7b9a1d023c34f0053432b9871d5aff2d7f4231ce186bda754604b2e664c5762ef81f557506bb35d16522864d67c2c1b014ba44fb2b93155a167ba75c1bed38084e2025db424a39f46e09a576ce1c6b6e938cf68e2277597e0890b00c9626e0260fdfc08df0950d9302402c04afd3dea08ccc69c8877562a5d60d21caab20893a9977b15326a96a3f4e641e5ab77c69309e30d0f7cdb568e7e1d179c28679185edf566aff4973ef167f04fb769695769e503236361042a856dc2988e5b64a2dfd048e28aebb6ad153b1512cb4a5c03a8a8d949248fb74882896ebf430d299ebeff912a3558329cfbf553b5f1fd3d3da7138eb293a4929035da2305913645eb68305d9e1ea49f33af352f02d38133d4873766b07d287dd0221f4a8dd40ca5661e99edb67500e3b92e82bc2666ec9c61071427371817c0253468558df0e808660a6c4a9fef4e1e81c6288b6e6f3d48ca2c81e3c8155cfe89a1d9d3566ef2ebfc"),
                ArrayConverter.hexStringToByteArray(
                    "8ed4198be5099c96ac923d54300717dc24814cc2aa0405556084f2d6ce4e48935db7461a74f319768686182afdbbc819c0c222643f1adc492f889f3627bea1affb523a1574eb778cbc985808074a9b8fe7f09705b1fbb9159e7a64e26c99859a69c5a9a36c02961ff1ba68363ade466ba1ed4413d10767d960dc577fd88e20df1fbacc46694d2b36c8683f96703561d779a1d329bb2c51b804097a45602eebdef79f8ce17aa1867b6f10a83b609a9efe0eec0d169d1b827b1990583bd97dcc390e5356fb0f6c27b784656716320eae45ef4cebb99d030a7e10053e96f58c8128a6aa19ceb7de70c249485ba9fd75ee91637485c99bc5a895900e594950641025")))
        // TODO: The following test vectors are broken (missing algorithms?)
        /*
         * Arguments.of("TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256.pcapng", List.of( ArrayConverter.hexStringToByteArray(
         * "045ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032"
         * ))), Arguments.of("psk_captured.pcang", List.of( ArrayConverter.hexStringToByteArray(
         * "8ed4198be5099c96ac923d54300717dc24814cc2aa0405556084f2d6ce4e48935db7461a74f319768686182afdbbc819c0c222643f1adc492f889f3627bea1affb523a1574eb778cbc985808074a9b8fe7f09705b1fbb9159e7a64e26c99859a69c5a9a36c02961ff1ba68363ade466ba1ed4413d10767d960dc577fd88e20df1fbacc46694d2b36c8683f96703561d779a1d329bb2c51b804097a45602eebdef79f8ce17aa1867b6f10a83b609a9efe0eec0d169d1b827b1990583bd97dcc390e5356fb0f6c27b784656716320eae45ef4cebb99d030a7e10053e96f58c8128a6aa19ceb7de70c249485ba9fd75ee91637485c99bc5a895900e594950641025"
         * ))), Arguments.of("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.pcapng", List.of( ArrayConverter.hexStringToByteArray(
         * "045ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032"
         * )))
         */
        );
    }

    @ParameterizedTest
    @MethodSource("providePremasterSecretExtractionTestVectors")
    public void testExtractEncryptedPremasterSecret(String providedPcapFile, List<byte[]> expectedPmsValues) {
        PcapAnalyzer sample = new PcapAnalyzer(String.format("src/test/resources/pcap_files/%s", providedPcapFile));
        List<PcapSession> sessions = sample.getAllSessions();
        for (int i = 0; i < expectedPmsValues.size(); i++) {
            byte[] pms = sessions.get(i).getPreMasterSecret();
            assertArrayEquals(expectedPmsValues.get(i), pms, "Mismatch in expected premaster secret with id " + i);
        }
    }

    @Test
    public void testExtractSessions() {
        List<PcapSession> sessions = fetchSessions("TLS_PSK_WITH_ARIA_128_CBC_SHA256.pcapng");
        assertEquals(4, sessions.size(), "NUMBER OF SESSION PRESENT IN THE FILE");
    }

    @Test
    @Tag(TestCategories.SLOW_TEST)
    public void testExtractSessionsSlow() {
        List<PcapSession> sessions = fetchSessions("Sample5.pcapng");
        assertTrue((sessions.size() >= 48 && sessions.size() < 52), "Error in reading correct number of sessions");
    }
}
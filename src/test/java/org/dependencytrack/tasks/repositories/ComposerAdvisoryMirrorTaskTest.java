/*
 * Copyright 2022 OWASP.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.dependencytrack.tasks.repositories;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_ENABLED;
import static org.junit.Assert.assertNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

import java.io.File;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.function.Consumer;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpHeaders;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Repository;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.composer.ComposerAdvisoryParser;
import org.dependencytrack.parser.composer.ComposerAdvisoryParserTest;
import org.dependencytrack.parser.composer.model.ComposerAdvisory;
import org.json.JSONObject;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockserver.client.MockServerClient;
import org.mockserver.integration.ClientAndServer;

import com.github.packageurl.PackageURL;

import alpine.model.IConfigProperty;


public class ComposerAdvisoryMirrorTaskTest extends PersistenceCapableTest {

    private static ClientAndServer mockServer;

    private static final String CONFIG_MIRROR_ENABLED_WITH_ALIAS = "{\"advisoryMirroringEnabled\": true, \"advisoryAliasSyncEnabled\": true}";

    @Before
    public void setUp() {
        qm.createConfigProperty(VULNERABILITY_SOURCE_NVD_ENABLED.getGroupName(),
                VULNERABILITY_SOURCE_NVD_ENABLED.getPropertyName(),
                "true",
                IConfigProperty.PropertyType.BOOLEAN,
                "");
        qm.createConfigProperty(VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED.getGroupName(),
                VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED.getPropertyName(),
                "true",
                IConfigProperty.PropertyType.BOOLEAN,
                "");

        mockServer.reset();
    }

    @BeforeClass
    public static void beforeClass() {
            mockServer = ClientAndServer.startClientAndServer(1080);
    }

    @AfterClass
    public static void afterClass() {
            mockServer.stop();
    }

    @Test
    public void testTruncateSummaryAndAffectedVersions() {
        String longTitle = "In uvc_scan_chain_forward of uvc_driver.c, there is a possible linked list corruption due to an unusual root cause. This could lead to local escalation of privilege in the kernel with no additional execution privileges needed. User interaction is not needed for exploitation.";
        ComposerAdvisoryMirrorTask task = new ComposerAdvisoryMirrorTask();
        ComposerAdvisory composerAdvisory = ComposerAdvisoryParser
                .parseAdvisory(ComposerAdvisoryParserTest.VULN_FOP);
        composerAdvisory.setTitle(longTitle);
        Vulnerability vuln = task.mapComposerAdvisoryToVulnerability(composerAdvisory, true);
        Assert.assertEquals(vuln.getTitle(), StringUtils.abbreviate(longTitle, "...", 255));

        String longAffected = "\\u003E=8.0.0,\\u003C8.1.0|\\u003E=8.1.0,\\u003C8.2.0|\\u003E=8.2.0,\\u003C8.3.0|\\u003E=8.3.0,\\u003C8.4.0|\\u003E=8.4.0,\\u003C8.5.0|\\u003E=8.5.0,\\u003C8.6.0|\\u003E=8.6.0,\\u003C8.7.0|\\u003E=8.7.0,\\u003C8.8.0|\\u003E=8.8.0,\\u003C8.9.0|\\u003E=8.9.0,\\u003C9.0.0|\\u003E=9.0.0,\\u003C9.1.0|\\u003E=9.1.0,\\u003C9.2.0|\\u003E=9.2.0,\\u003C9.3.0|\\u003E=9.3.0,\\u003C9.4.0|\\u003E=9.4.0,\\u003C9.5.0|\\u003E=9.5.0,\\u003C10.0.0|\\u003E=10.0.0,\\u003C10.1.0|\\u003E=10.1.0,\\u003C10.1.8|\\u003E=10.2.0,\\u003C10.2.2";
        composerAdvisory = ComposerAdvisoryParser.parseAdvisory(ComposerAdvisoryParserTest.VULN_FOP);
        composerAdvisory.setAffectedVersionsCve(longAffected);
        vuln = task.mapComposerAdvisoryToVulnerability(composerAdvisory, true);
        Assert.assertEquals(vuln.getVulnerableVersions(), StringUtils.abbreviate(longAffected, "...", 255));
    }

    @Test
    public void testextractVulnIdDrupal() {
        Vulnerability.Source source1 = Vulnerability.Source.resolve(ComposerAdvisoryMirrorTask
                .extractVulnId(ComposerAdvisoryParser.parseAdvisory(ComposerAdvisoryParserTest.VULN_DRUPAL)));
        Assert.assertEquals(Vulnerability.Source.DRUPAL, source1);
    }

    @Test
    public void testextractVulnIdFriendsOfPhp() {
        Vulnerability.Source source2 = Vulnerability.Source.resolve(ComposerAdvisoryMirrorTask
                .extractVulnId(ComposerAdvisoryParser.parseAdvisory(ComposerAdvisoryParserTest.VULN_FOP)));
        Assert.assertEquals(Vulnerability.Source.GITHUB, source2);
    }

    @Test
    public void testextractVulnIdGHSA() {
        Vulnerability.Source source3 = Vulnerability.Source.resolve(ComposerAdvisoryMirrorTask
                .extractVulnId(ComposerAdvisoryParser.parseAdvisory(ComposerAdvisoryParserTest.VULN_GHSA)));
        Assert.assertEquals(Vulnerability.Source.GITHUB, source3);
    }

    @Test
    public void testextractVulnIdFriendsOfPhpCVE() {
        Vulnerability.Source source4 = Vulnerability.Source.resolve(ComposerAdvisoryMirrorTask
                .extractVulnId(ComposerAdvisoryParser.parseAdvisory(ComposerAdvisoryParserTest.VULN_FOP_CVE)));
        Assert.assertEquals(Vulnerability.Source.NVD, source4);
    }

    @Test
    public void testextractVulnIdFriendsOfPhpNoCVE() {
        Vulnerability.Source source4 = Vulnerability.Source.resolve(ComposerAdvisoryMirrorTask
                .extractVulnId(ComposerAdvisoryParser.parseAdvisory(ComposerAdvisoryParserTest.VULN_FOP_NO_CVE)));
        Assert.assertEquals(Vulnerability.Source.GITHUB, source4);
    }

    @Test
    public void testextractVulnIdComposer() {
        Vulnerability.Source source5 = Vulnerability.Source.resolve(ComposerAdvisoryMirrorTask
                .extractVulnId(ComposerAdvisoryParser.parseAdvisory(ComposerAdvisoryParserTest.VULN_COMPOSER)));
        Assert.assertEquals(Vulnerability.Source.COMPOSER, source5);
    }

    @Test
    public void testDrupalAffectedVersionMapping() throws IOException {
        ComposerAdvisory vuln = ComposerAdvisoryParser
                .parseAdvisory(ComposerAdvisoryParserTest.VULN_DRUPAL);
        ComposerAdvisoryMirrorTask task = new ComposerAdvisoryMirrorTask();
        List<VulnerableSoftware> mapVulnerabilityToVulnerableSoftware = task.mapVulnerabilityToVulnerableSoftware(qm,
                vuln);
        Assert.assertEquals(2, mapVulnerabilityToVulnerableSoftware.size());
        assertThat(mapVulnerabilityToVulnerableSoftware).satisfiesExactlyInAnyOrder(
                range -> {
                    assertThat(range.getVersionStartIncluding()).isEqualTo("8.0.0");
                    assertThat(range.getVersionEndExcluding()).isEqualTo("8.4.7");
                },
                range -> {
                    assertThat(range.getVersionStartIncluding()).isEqualTo("8.5.0");
                    assertThat(range.getVersionEndExcluding()).isEqualTo("8.5.2");
                });
    }

    @Test
    public void testPackagistAffectedVersionMapping() throws IOException {
        ComposerAdvisory vuln = ComposerAdvisoryParser
                .parseAdvisory(ComposerAdvisoryParserTest.VULN_FOP);
        ComposerAdvisoryMirrorTask task = new ComposerAdvisoryMirrorTask();
        List<VulnerableSoftware> mapVulnerabilityToVulnerableSoftware = task.mapVulnerabilityToVulnerableSoftware(qm,
                vuln);
        Assert.assertEquals(4, mapVulnerabilityToVulnerableSoftware.size());
        assertThat(mapVulnerabilityToVulnerableSoftware).satisfiesExactlyInAnyOrder(
                range -> {
                    assertThat(range.getVersionEndExcluding()).isEqualTo("1.8.1");
                },
                range -> {
                    assertThat(range.getVersionStartIncluding()).isEqualTo("1.9.0");
                    assertThat(range.getVersionEndExcluding()).isEqualTo("1.9.1");
                },
                range -> {
                    assertThat(range.getVersionStartIncluding()).isEqualTo("1.10");
                    assertThat(range.getVersionEndExcluding()).isEqualTo("1.10.3");
                },
                range -> {
                    assertThat(range.getVersionStartIncluding()).isEqualTo("2.0");
                    assertThat(range.getVersionEndExcluding()).isEqualTo("2.3.3");
                });
    }

    // TODO VS Test "*"
    // TODO VS Test exact versions

    @Test
    public void testDrupalAdvisory() throws Exception {
        doDrupalAdvisory(true);
    }

    @Test
    public void testDrupalAdvisorySkipAliases() throws Exception {
        doDrupalAdvisory(false);
    }

    public void doDrupalAdvisory(boolean aliasSync) throws Exception {
        ComposerAdvisory advisory = ComposerAdvisoryParser.parseAdvisory(ComposerAdvisoryParserTest.VULN_DRUPAL);
        Assert.assertNotNull(advisory);

        ComposerAdvisoryMirrorTask task = new ComposerAdvisoryMirrorTask();

        task.processAdvisory(qm, advisory, aliasSync);

        final Consumer<Vulnerability> assertVulnerability = (vulnerability) -> {
            Assert.assertNotNull(vulnerability);
            Assert.assertEquals("SA-CORE-2018-003", vulnerability.getVulnId());
            Assert.assertEquals("DRUPAL", vulnerability.getSource());
            Assert.assertEquals(">= 8.0.0 <8.4.7 || >=8.5.0 <8.5.2", vulnerability.getVulnerableVersions());
            Assert.assertFalse(StringUtils.isEmpty(vulnerability.getTitle()));
            Assert.assertFalse(StringUtils.isEmpty(vulnerability.getDescription()));
            Assert.assertEquals(Severity.UNASSIGNED, vulnerability.getSeverity());
            Assert.assertNull(vulnerability.getCreated());
            Assert.assertNotNull(vulnerability.getPublished());
            Assert.assertEquals(LocalDateTime.of(2018, 4, 18, 15, 34, 9).toInstant(ZoneOffset.UTC),
                    vulnerability.getPublished().toInstant());
            Assert.assertNotNull(vulnerability.getUpdated());
            Assert.assertEquals(LocalDateTime.of(2018, 4, 18, 15, 34, 9).toInstant(ZoneOffset.UTC),
                    vulnerability.getUpdated().toInstant());
        };

        Vulnerability vulnerability = qm.getVulnerabilityByVulnId("DRUPAL", "SA-CORE-2018-003", true);
        assertVulnerability.accept(vulnerability);

        List<VulnerableSoftware> vulnerableSoftware = qm.getAllVulnerableSoftwareByPurl(
                new PackageURL("pkg:composer/drupal/core"));
        Assert.assertEquals(2, vulnerableSoftware.size());
        Assert.assertEquals("8.0.0", vulnerableSoftware.get(0).getVersionStartIncluding());
        Assert.assertEquals("8.4.7", vulnerableSoftware.get(0).getVersionEndExcluding());
        Assert.assertEquals("8.5.0", vulnerableSoftware.get(1).getVersionStartIncluding());
        Assert.assertEquals("8.5.2", vulnerableSoftware.get(1).getVersionEndExcluding());

        final List<VulnerabilityAlias> aliases = qm.getVulnerabilityAliases(vulnerability);
        Assert.assertEquals(aliasSync ? 1 : 0, aliases.size());
        if (aliasSync) {
            assertThat(aliases).satisfiesExactly(
                    alias -> {
                        assertNull(alias.getComposerId());
                        assertEquals("CVE-2018-9861", alias.getCveId());
                        assertNull(alias.getGhsaId());
                        assertEquals("SA-CORE-2018-003", alias.getDrupalId());
                        assertNull(alias.getGsdId());
                        assertNull(alias.getInternalId());
                        assertNull(alias.getOsvId());
                        assertNull(alias.getSnykId());
                        assertNull(alias.getSonatypeId());
                        assertNull(alias.getVulnDbId());
                    });
        }
    }

    @Test
    public void testFop() throws Exception {
        doFop(true);
    }

    @Test
    public void testFopSkipAliases() throws Exception {
        doFop(false);
    }

    public void doFop(boolean aliasSync) throws Exception {
        ComposerAdvisory advisory = ComposerAdvisoryParser.parseAdvisory(ComposerAdvisoryParserTest.VULN_FOP);
        Assert.assertNotNull(advisory);

        ComposerAdvisoryMirrorTask task = new ComposerAdvisoryMirrorTask();

        task.processAdvisory(qm, advisory, aliasSync);

        final Consumer<Vulnerability> assertVulnerability = (vulnerability) -> {
            Assert.assertNotNull(vulnerability);
            Assert.assertEquals("GHSA-r8v4-7vwj-983x", vulnerability.getVulnId());
            Assert.assertEquals("GITHUB", vulnerability.getSource());
            Assert.assertEquals("<1.8.1|>=1.9.0,<1.9.1|>=1.10,<1.10.3|>=2.0,<2.3.3",
                    vulnerability.getVulnerableVersions());
            Assert.assertFalse(StringUtils.isEmpty(vulnerability.getTitle()));
            Assert.assertFalse(StringUtils.isEmpty(vulnerability.getDescription()));
            Assert.assertEquals(Severity.CRITICAL, vulnerability.getSeverity());
            Assert.assertNull(vulnerability.getCreated());
            Assert.assertNotNull(vulnerability.getPublished());
            Assert.assertEquals(LocalDateTime.of(2016, 11, 29, 13, 12, 44).toInstant(ZoneOffset.UTC),
                    vulnerability.getPublished().toInstant());
            Assert.assertNotNull(vulnerability.getUpdated());
            Assert.assertEquals(LocalDateTime.of(2016, 11, 29, 13, 12, 44).toInstant(ZoneOffset.UTC),
                    vulnerability.getUpdated().toInstant());
        };

        Vulnerability vulnerability = qm.getVulnerabilityByVulnId(Vulnerability.Source.GITHUB, "GHSA-r8v4-7vwj-983x", true);
        assertVulnerability.accept(vulnerability);

        List<VulnerableSoftware> vulnerableSoftware = qm.getAllVulnerableSoftwareByPurl(
            new PackageURL("pkg:composer/simplesamlphp/saml2"));

        Assert.assertEquals(4, vulnerableSoftware.size());
        Assert.assertEquals("1.8.1", vulnerableSoftware.get(0).getVersionEndExcluding());
        Assert.assertEquals("1.9.0", vulnerableSoftware.get(1).getVersionStartIncluding());
        Assert.assertEquals("1.9.1", vulnerableSoftware.get(1).getVersionEndExcluding());
        //Is this ok, or should it become 1.10.0?
        Assert.assertEquals("1.10", vulnerableSoftware.get(2).getVersionStartIncluding());
        Assert.assertEquals("1.10.3", vulnerableSoftware.get(2).getVersionEndExcluding());
        Assert.assertEquals("2.0", vulnerableSoftware.get(3).getVersionStartIncluding());
        Assert.assertEquals("2.3.3", vulnerableSoftware.get(3).getVersionEndExcluding());

        final List<VulnerabilityAlias> aliases = qm.getVulnerabilityAliases(vulnerability);
        Assert.assertEquals(aliasSync ? 1 : 0, aliases.size());
        if (aliasSync) {
            assertThat(aliases).satisfiesExactly(
                    alias -> {
                        assertNull(alias.getComposerId());
                        assertEquals("CVE-2016-9814", alias.getCveId());
                        assertEquals("GHSA-r8v4-7vwj-983x", alias.getGhsaId());
                        assertNull(alias.getDrupalId());
                        assertNull(alias.getGsdId());
                        assertNull(alias.getInternalId());
                        assertNull(alias.getOsvId());
                        assertNull(alias.getSnykId());
                        assertNull(alias.getSonatypeId());
                        assertNull(alias.getVulnDbId());
                    });
        }
    }

    @Test
    public void testFopCve() throws Exception {
        doFop(true);
    }

    @Test
    public void testFopCveSkipAliases() throws Exception {
        doFop(false);
    }

    public void doFopCve(boolean aliasSync) throws Exception {
        ComposerAdvisory advisory = ComposerAdvisoryParser.parseAdvisory(ComposerAdvisoryParserTest.VULN_FOP_CVE);
        Assert.assertNotNull(advisory);

        ComposerAdvisoryMirrorTask task = new ComposerAdvisoryMirrorTask();

        task.processAdvisory(qm, advisory, aliasSync);

        final Consumer<Vulnerability> assertVulnerability = (vulnerability) -> {
            Assert.assertNotNull(vulnerability);
            Assert.assertEquals("CVE-2016-9814", vulnerability.getVulnId());
            Assert.assertEquals("NVD", vulnerability.getSource());
            Assert.assertEquals("<1.8.1|>=1.9.0,<1.9.1|>=1.10,<1.10.3|>=2.0,<2.3.3",
                    vulnerability.getVulnerableVersions());
            Assert.assertFalse(StringUtils.isEmpty(vulnerability.getTitle()));
            Assert.assertFalse(StringUtils.isEmpty(vulnerability.getDescription()));
            Assert.assertEquals(Severity.CRITICAL, vulnerability.getSeverity());
            Assert.assertNull(vulnerability.getCreated());
            Assert.assertNotNull(vulnerability.getPublished());
            Assert.assertEquals(LocalDateTime.of(2016, 11, 29, 13, 12, 44).toInstant(ZoneOffset.UTC),
                    vulnerability.getPublished().toInstant());
            Assert.assertNotNull(vulnerability.getUpdated());
            Assert.assertEquals(LocalDateTime.of(2016, 11, 29, 13, 12, 44).toInstant(ZoneOffset.UTC),
                    vulnerability.getUpdated().toInstant());
        };

        Vulnerability vulnerability = qm.getVulnerabilityByVulnId(Vulnerability.Source.NVD, "CVE-2016-9814", true);
        assertVulnerability.accept(vulnerability);

        List<VulnerableSoftware> vulnerableSoftware = qm.getAllVulnerableSoftwareByPurl(
            new PackageURL("pkg:composer/simplesamlphp/saml2"));

        Assert.assertEquals(4, vulnerableSoftware.size());
        Assert.assertEquals("1.8.1", vulnerableSoftware.get(0).getVersionEndExcluding());
        Assert.assertEquals("1.9.0", vulnerableSoftware.get(1).getVersionStartIncluding());
        Assert.assertEquals("1.9.1", vulnerableSoftware.get(1).getVersionEndExcluding());
        //Is this ok, or should it become 1.10.0?
        Assert.assertEquals("1.10", vulnerableSoftware.get(2).getVersionStartIncluding());
        Assert.assertEquals("1.10.3", vulnerableSoftware.get(2).getVersionEndExcluding());
        Assert.assertEquals("2.0", vulnerableSoftware.get(3).getVersionStartIncluding());
        Assert.assertEquals("2.3.3", vulnerableSoftware.get(3).getVersionEndExcluding());

        final List<VulnerabilityAlias> aliases = qm.getVulnerabilityAliases(vulnerability);
        Assert.assertEquals(aliasSync ? 1 : 0, aliases.size());
        if (aliasSync) {
            assertThat(aliases).satisfiesExactly(
                    alias -> {
                        assertNull(alias.getComposerId());
                        assertEquals("CVE-2016-9814", alias.getCveId());
                        assertNull(alias.getDrupalId());
                        assertNull(alias.getGsdId());
                        assertNull(alias.getInternalId());
                        assertNull(alias.getOsvId());
                        assertNull(alias.getSnykId());
                        assertNull(alias.getSonatypeId());
                        assertNull(alias.getVulnDbId());
                    });
        }
    }


    @Test
    public void testFopNoCve() throws Exception {
        doFopNoCve(true);
    }

    @Test
    public void testFopNoCveSkipAliases() throws Exception {
        doFopNoCve(false);
    }

    public void doFopNoCve(boolean aliasSync) throws Exception {
        ComposerAdvisory advisory = ComposerAdvisoryParser.parseAdvisory(ComposerAdvisoryParserTest.VULN_FOP_NO_CVE);
        Assert.assertNotNull(advisory);

        ComposerAdvisoryMirrorTask task = new ComposerAdvisoryMirrorTask();

        task.processAdvisory(qm, advisory, aliasSync);

        final Consumer<Vulnerability> assertVulnerability = (vulnerability) -> {
            Assert.assertNotNull(vulnerability);
            Assert.assertEquals("GHSA-7v68-3pr5-h3cr", vulnerability.getVulnId());
            Assert.assertEquals("GITHUB", vulnerability.getSource());
            Assert.assertEquals(">=8.0.0,<8.1.0|>=8.1.0,<8.2.0|>=8.2.0,<8.3.0|>=8.3.0,<8.4.0|>=8.4.0,<8.5.0|>=8.5.0,<8.6.0|>=8.6.0,<8.7.0|>=8.7.0,<8.7.11|>=8.8.0,<8.8.1",
                    vulnerability.getVulnerableVersions());
            Assert.assertFalse(StringUtils.isEmpty(vulnerability.getTitle()));
            Assert.assertFalse(StringUtils.isEmpty(vulnerability.getDescription()));
            Assert.assertEquals(Severity.CRITICAL, vulnerability.getSeverity());
            Assert.assertNull(vulnerability.getCreated());
            Assert.assertNotNull(vulnerability.getPublished());
            Assert.assertEquals(LocalDateTime.of(2019, 12, 18, 0, 0, 0).toInstant(ZoneOffset.UTC),
                    vulnerability.getPublished().toInstant());
            Assert.assertNotNull(vulnerability.getUpdated());
            Assert.assertEquals(LocalDateTime.of(2019, 12, 18, 0, 0, 0).toInstant(ZoneOffset.UTC),
                    vulnerability.getUpdated().toInstant());
        };

        Vulnerability vulnerability = qm.getVulnerabilityByVulnId(Vulnerability.Source.GITHUB, "GHSA-7v68-3pr5-h3cr", true);
        assertVulnerability.accept(vulnerability);

        List<VulnerableSoftware> vulnerableSoftware = qm.getAllVulnerableSoftwareByPurl(
            new PackageURL("pkg:composer/drupal/core"));

        Assert.assertEquals(9, vulnerableSoftware.size());
        Assert.assertEquals("8.0.0", vulnerableSoftware.get(0).getVersionStartIncluding());
        Assert.assertEquals("8.1.0", vulnerableSoftware.get(0).getVersionEndExcluding());
        Assert.assertEquals("8.1.0", vulnerableSoftware.get(1).getVersionStartIncluding());
        Assert.assertEquals("8.2.0", vulnerableSoftware.get(1).getVersionEndExcluding());
        //Is this ok, or should it become 1.10.0?
        Assert.assertEquals("8.2.0", vulnerableSoftware.get(2).getVersionStartIncluding());
        Assert.assertEquals("8.3.0", vulnerableSoftware.get(2).getVersionEndExcluding());
        Assert.assertEquals("8.3.0", vulnerableSoftware.get(3).getVersionStartIncluding());
        Assert.assertEquals("8.4.0", vulnerableSoftware.get(3).getVersionEndExcluding());

        Assert.assertEquals("8.4.0", vulnerableSoftware.get(4).getVersionStartIncluding());
        Assert.assertEquals("8.5.0", vulnerableSoftware.get(4).getVersionEndExcluding());
        Assert.assertEquals("8.5.0", vulnerableSoftware.get(5).getVersionStartIncluding());
        Assert.assertEquals("8.6.0", vulnerableSoftware.get(5).getVersionEndExcluding());
        Assert.assertEquals("8.6.0", vulnerableSoftware.get(6).getVersionStartIncluding());
        Assert.assertEquals("8.7.0", vulnerableSoftware.get(6).getVersionEndExcluding());
        Assert.assertEquals("8.7.0", vulnerableSoftware.get(7).getVersionStartIncluding());
        Assert.assertEquals("8.7.11", vulnerableSoftware.get(7).getVersionEndExcluding());
        Assert.assertEquals("8.8.0", vulnerableSoftware.get(8).getVersionStartIncluding());
        Assert.assertEquals("8.8.1", vulnerableSoftware.get(8).getVersionEndExcluding());

        final List<VulnerabilityAlias> aliases = qm.getVulnerabilityAliases(vulnerability);
        Assert.assertEquals(aliasSync ? 0 : 0, aliases.size());
    }

    @Test
    public void testGHSAAdvisory() throws Exception {
        doGHSAAdvisory(true);
    }

    @Test
    public void testGHSAAdvisorySkipAliases() throws Exception {
        doGHSAAdvisory(false);
    }


    // public final static JSONObject vulnGHSA = new JSONObject("""
    //     {
    //         "advisoryId": "PKSA-228k-hrjg-43zp",
    //         "packageName": "magento/community-edition",
    //         "remoteId": "GHSA-297f-r9w7-w492",
    //         "title": "Magento Improper input validation vulnerability",
    //         "link": "https://github.com/advisories/GHSA-297f-r9w7-w492",
    //         "cve": "CVE-2022-42344",
    //         "affectedVersions": "=2.4.4|>=2.4.0,<2.4.3-p3|<2.3.7-p4",
    //         "source": "GitHub",
    //         "reportedAt": "2022-10-20 19:00:29",
    //         "composerRepository": "https://packagist.org",
    //         "severity": "high",
    //         "sources": [
    //             {
    //                 "name": "GitHub",
    //                 "remoteId": "GHSA-297f-r9w7-w492"
    //             }
    //         ]
    //     }
    // """);

    public void doGHSAAdvisory(boolean aliasSync) throws Exception {
        ComposerAdvisory advisory = ComposerAdvisoryParser.parseAdvisory(ComposerAdvisoryParserTest.VULN_GHSA);
        Assert.assertNotNull(advisory);

        ComposerAdvisoryMirrorTask task = new ComposerAdvisoryMirrorTask();

        task.processAdvisory(qm, advisory, aliasSync);

        final Consumer<Vulnerability> assertVulnerability = (vulnerability) -> {
            Assert.assertNotNull(vulnerability);
            Assert.assertEquals("GHSA-297f-r9w7-w492", vulnerability.getVulnId());
            Assert.assertEquals("GITHUB", vulnerability.getSource());
            Assert.assertEquals("=2.4.4|>=2.4.0,<2.4.3-p3|<2.3.7-p4",
                    vulnerability.getVulnerableVersions());
            Assert.assertFalse(StringUtils.isEmpty(vulnerability.getTitle()));
            Assert.assertFalse(StringUtils.isEmpty(vulnerability.getDescription()));
            Assert.assertEquals(Severity.HIGH, vulnerability.getSeverity());
            Assert.assertNull(vulnerability.getCreated());
            Assert.assertNotNull(vulnerability.getPublished());
            Assert.assertEquals(LocalDateTime.of(2022, 10, 20, 19, 00, 29).toInstant(ZoneOffset.UTC),
                    vulnerability.getPublished().toInstant());
            Assert.assertNotNull(vulnerability.getUpdated());
            Assert.assertEquals(LocalDateTime.of(2022, 10, 20, 19, 00, 29).toInstant(ZoneOffset.UTC),
                    vulnerability.getUpdated().toInstant());
        };

        Vulnerability vulnerability = qm.getVulnerabilityByVulnId(Vulnerability.Source.GITHUB, "GHSA-297f-r9w7-w492", true);
        assertVulnerability.accept(vulnerability);

        List<VulnerableSoftware> vulnerableSoftware = qm.getAllVulnerableSoftwareByPurl(
                new PackageURL("pkg:composer/magento/community-edition"));
        Assert.assertEquals(3, vulnerableSoftware.size());
        Assert.assertEquals("2.4.4", vulnerableSoftware.get(0).getVersionStartIncluding());
        Assert.assertEquals("2.4.4", vulnerableSoftware.get(0).getVersionEndIncluding());
        Assert.assertEquals("2.4.0", vulnerableSoftware.get(1).getVersionStartIncluding());
        Assert.assertEquals("2.4.3-p3", vulnerableSoftware.get(1).getVersionEndExcluding());
        Assert.assertEquals("2.3.7-p4", vulnerableSoftware.get(2).getVersionEndExcluding());

        final List<VulnerabilityAlias> aliases = qm.getVulnerabilityAliases(vulnerability);
        Assert.assertEquals(aliasSync ? 1 : 0, aliases.size());
        if (aliasSync) {
            assertThat(aliases).satisfiesExactly(
                    alias -> {
                        assertNull(alias.getComposerId());
                        assertThat(alias.getCveId().equals("CVE-2022-42344"));
                        assertThat(alias.getGhsaId().equals("GHSA-r8v4-7vwj-983x"));
                        assertNull(alias.getDrupalId());
                        assertNull(alias.getGsdId());
                        assertNull(alias.getInternalId());
                        assertNull(alias.getOsvId());
                        assertNull(alias.getSnykId());
                        assertNull(alias.getSonatypeId());
                        assertNull(alias.getVulnDbId());
                    });
        }
    }

    @Test
    public void testPackagistAdvisories() throws Exception {
        ComposerAdvisoryMirrorTask task = new ComposerAdvisoryMirrorTask();

        final File advisoryFile = ComposerMetaAnalyzerTest.getRepoResourceFile("repo.packagist.org", "advisories");
        final File packagistRepoRootFile = ComposerMetaAnalyzerTest.getRepoResourceFile("repo.packagist.org", "packages");

        @SuppressWarnings("resource")
        MockServerClient mockClient = new MockServerClient("localhost", mockServer.getPort());
        String mockUrl = String.format("http://localhost:%d", mockServer.getPort());
        mockClient.when(
                        request()
                                        .withMethod("GET")
                                        .withPath("/packages.json"))
                        .respond(
                                        response()
                                                        .withStatusCode(200)
                                                        .withHeader(HttpHeaders.CONTENT_TYPE,
                                                                        "application/json")
                                                        .withBody(getRepoRootForMock(packagistRepoRootFile, mockUrl)));

        mockClient.when(
                        request()
                                        .withMethod("GET")
                                        .withPath("/api/security-advisories")
                                        .withQueryStringParameter("updatedSince", "100")
                                        )
                        .respond(
                                        response()
                                                        .withStatusCode(200)
                                                        .withHeader(HttpHeaders.CONTENT_TYPE,
                                                                        "application/json")
                                                        .withBody(new String(ComposerMetaAnalyzerTest.getTestData(advisoryFile))));

        Repository repo = qm.createRepository(RepositoryType.COMPOSER, "packagist", mockUrl, true, false, false, null, null, CONFIG_MIRROR_ENABLED_WITH_ALIAS);
        boolean mirroredWithoutErrors = task.mirrorAdvisories(qm, repo);

        Assert.assertTrue(mirroredWithoutErrors);

        Assert.assertEquals(10, qm.getVulnerabilities().getTotal());

        //Vulnerabilities should not have PKSA ids if other IDs are present
        Assert.assertNull(qm.getVulnerabilityByVulnId(Vulnerability.Source.COMPOSER, "PKSA-q4rt-5vfc-wksb"));
        Vulnerability vulnerability1 = qm.getVulnerabilityByVulnId(Vulnerability.Source.GITHUB, "GHSA-2697-96mv-3gfm");

        Assert.assertNotNull(vulnerability1);

        Assert.assertEquals("GHSA-2697-96mv-3gfm", vulnerability1.getVulnId());
        Assert.assertEquals("CVE-2024-50701", vulnerability1.getAliases().get(0).getCveId());
        Assert.assertNull(vulnerability1.getAliases().get(0).getComposerId());

    // TODO VS Test CVE with existing vuln
    // TODO VS Test GHSA with existing vuln


    }

    private String getRepoRootForMock(File file, String mockUrl) throws Exception {
        String data = new String(ComposerMetaAnalyzerTest.getTestData(file));
        JSONObject json = new JSONObject(data);

        json.getJSONObject("security-advisories").put("api-url", mockUrl + "/api/security-advisories");
        return json.toString();
    }


}

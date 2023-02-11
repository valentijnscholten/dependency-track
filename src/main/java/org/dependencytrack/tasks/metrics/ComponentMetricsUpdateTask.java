/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.tasks.metrics;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.apache.commons.lang3.time.DurationFormatUtils;
import org.dependencytrack.event.ComponentMetricsUpdateEvent;
import org.dependencytrack.metrics.Metrics;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.ViolationAnalysis;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.persistence.QueryManager;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;

import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.UUID;

import static java.lang.Math.toIntExact;

/**
 * A {@link Subscriber} task that updates {@link Component} metrics.
 *
 * @since 4.6.0
 */
public class ComponentMetricsUpdateTask implements Subscriber {

    private static final Logger LOGGER = Logger.getLogger(ComponentMetricsUpdateTask.class);

    @Override
    public void inform(final Event e) {
        if (e instanceof final ComponentMetricsUpdateEvent event) {
            try {
                updateMetrics(event.uuid());
            } catch (Exception ex) {
                LOGGER.error("An unexpected error occurred while updating metrics of component " + event.uuid(), ex);
            }
        }
    }

    private Counters updateMetrics(final UUID uuid) throws Exception {
        try (final var qm = new QueryManager()) {
            final Component component = qm.getObjectByUuid(Component.class, uuid, List.of(Component.FetchGroup.METRICS_UPDATE.name()));
            if (component == null) {
                throw new NoSuchElementException("Component " + uuid + " does not exist");
            }
            return updateMetrics(qm, component);
        }
    }

    static Counters updateMetrics(final QueryManager qm, final Component component) throws Exception {
        LOGGER.debug("Executing metrics update for component " + component.getUuid());
        final var counters = new Counters();

        // final Component component = qm.getObjectByUuid(Component.class, uuid, List.of(Component.FetchGroup.METRICS_UPDATE.name()));
        // if (component == null) {
        //     throw new NoSuchElementException("Component " + uuid + " does not exist");
        // }

        final PersistenceManager pm = qm.getPersistenceManager();
        final Set<String> aliasesSeen = new HashSet<>();

        for (final Vulnerability vulnerability : getVulnerabilities(pm, component)) {
            // Quick pre-flight check whether we already encountered an alias of this particular vulnerability
            final String alias = vulnerability.getSource() + "|" + vulnerability.getVulnId();
            if (aliasesSeen.contains(alias)) {
                LOGGER.debug("An alias of " + alias + " has already been processed; Skipping");
                continue;
            }

            // Fetch all aliases for this vulnerability and consider all of them as "seen"
            LOGGER.debug("Getting vulnerability aliases for vulnerability " + vulnerability.getUuid());            
            qm.getVulnerabilityAliases(vulnerability).stream()
                    .map(VulnerabilityAlias::getAllBySource)
                    .flatMap(vulnIdsBySource -> vulnIdsBySource.entrySet().stream())
                    .map(vulnIdBySource -> vulnIdBySource.getKey() + "|" + vulnIdBySource.getValue())
                    .forEach(aliasesSeen::add);

            counters.vulnerabilities++;

            switch (vulnerability.getSeverity()) {
                case CRITICAL -> counters.critical++;
                case HIGH -> counters.high++;
                case MEDIUM -> counters.medium++;
                case LOW, INFO -> counters.low++;
                case UNASSIGNED -> counters.unassigned++;
            }
        }

        counters.findingsTotal = toIntExact(counters.vulnerabilities);
        counters.findingsAudited = toIntExact(getTotalAuditedFindings(pm, component));
        counters.findingsUnaudited = counters.findingsTotal - counters.findingsAudited;
        counters.suppressions = toIntExact(getTotalSuppressedFindings(pm, component));
        counters.inheritedRiskScore = Metrics.inheritedRiskScore(counters.critical, counters.high, counters.medium, counters.low, counters.unassigned);

        for (final PolicyViolation violation : getPolicyViolations(pm, component)) {
            counters.policyViolationsTotal++;

            switch (violation.getType()) {
                case LICENSE -> counters.policyViolationsLicenseTotal++;
                case OPERATIONAL -> counters.policyViolationsOperationalTotal++;
                case SECURITY -> counters.policyViolationsSecurityTotal++;
            }

            switch (violation.getPolicyCondition().getPolicy().getViolationState()) {
                case FAIL -> counters.policyViolationsFail++;
                case WARN -> counters.policyViolationsWarn++;
                case INFO -> counters.policyViolationsInfo++;
            }
        }

        if (counters.policyViolationsLicenseTotal > 0) {
            counters.policyViolationsLicenseAudited = toIntExact(getTotalAuditedPolicyViolations(pm, component, PolicyViolation.Type.LICENSE));
            counters.policyViolationsLicenseUnaudited = counters.policyViolationsLicenseTotal - counters.policyViolationsLicenseAudited;
        }
        if (counters.policyViolationsOperationalTotal > 0) {
            counters.policyViolationsOperationalAudited = toIntExact(getTotalAuditedPolicyViolations(pm, component, PolicyViolation.Type.OPERATIONAL));
            counters.policyViolationsOperationalUnaudited = counters.policyViolationsOperationalTotal - counters.policyViolationsOperationalAudited;
        }
        if (counters.policyViolationsSecurityTotal > 0) {
            counters.policyViolationsSecurityAudited = toIntExact(getTotalAuditedPolicyViolations(pm, component, PolicyViolation.Type.SECURITY));
            counters.policyViolationsSecurityUnaudited = counters.policyViolationsSecurityTotal - counters.policyViolationsSecurityAudited;
        }

        counters.policyViolationsAudited = counters.policyViolationsLicenseAudited +
                counters.policyViolationsOperationalAudited +
                counters.policyViolationsSecurityAudited;
        counters.policyViolationsUnaudited = counters.policyViolationsTotal - counters.policyViolationsAudited;

        qm.runInTransaction(() -> {
            final DependencyMetrics latestMetrics = qm.getMostRecentDependencyMetrics(component);
            if (!counters.hasChanged(latestMetrics)) {
                LOGGER.debug("Metrics of component " + component.getUuid() + " did not change");
                latestMetrics.setLastOccurrence(counters.measuredAt);
            } else {
                LOGGER.debug("Metrics of component " + component.getUuid() + " changed");
                final DependencyMetrics metrics = counters.createComponentMetrics(component);
                pm.makePersistent(metrics);
            }
        });

        if (component.getLastInheritedRiskScore() == null ||
                component.getLastInheritedRiskScore() != counters.inheritedRiskScore) {
            LOGGER.debug("Updating inherited risk score of component " + component.getUuid());
            qm.runInTransaction(() -> component.setLastInheritedRiskScore(counters.inheritedRiskScore));
        }

        LOGGER.debug("Completed metrics update for component " + component.getUuid() + " in " +
                DurationFormatUtils.formatDuration(new Date().getTime() - counters.measuredAt.getTime(), "mm:ss:SS"));
        return counters;
    }

    @SuppressWarnings("unchecked")
<<<<<<< HEAD
    private static List<Vulnerability> getVulnerabilities(final PersistenceManager pm, final Component component) throws Exception {
        // Using the JDO single-string syntax here because we need to pass the parameter
        // of the outer query (the component) to the sub-query. For some reason that does
        // not work with the declarative JDO API.
        try (final Query<?> query = pm.newQuery(Query.JDOQL, """
                SELECT FROM org.dependencytrack.model.Vulnerability
                WHERE this.components.contains(:component)
                    && (SELECT FROM org.dependencytrack.model.Analysis a
                        WHERE a.component == :component
                            && a.vulnerability == this
                            && a.suppressed == true).isEmpty()
                """)) {
            query.setParameters(component);
            query.getFetchPlan().setGroup(Vulnerability.FetchGroup.METRICS_UPDATE.name());
            return List.copyOf((List<Vulnerability>) query.executeList());
        }
=======
    private static Collection<Vulnerability> getVulnerabilities(final PersistenceManager pm, final Component component) throws Exception {
        LOGGER.debug("Getting vulnerabilities for component " + component.getUuid());
        // final Collection<Vulnerability> vulnerabilities = pm.detachCopyAll(component.getVulnerabilities());
        // for (Analysis analysis: component.getAnalysises()) {
        //     if (analysis.isSuppressed()) {
        //         vulnerabilities.remove(analysis.getVulnerability());
        //     }
        // }
        // LOGGER.debug("Done Getting vulnerabilities for component " + component.getUuid());
        // return vulnerabilities;
        return component.getVulnerabilities();

        // // Using the JDO single-string syntax here because we need to pass the parameter
        // // of the outer query (the component) to the sub-query. For some reason that does
        // // not work with the declarative JDO API.
        // try (final Query<?> query = pm.newQuery(Query.JDOQL, """
        //         SELECT FROM org.dependencytrack.model.Vulnerability
        //         WHERE this.components.contains(:component)
        //             && (SELECT FROM org.dependencytrack.model.Analysis a
        //                 WHERE a.component == :component
        //                     && a.vulnerability == this
        //                     && a.suppressed == true).isEmpty()
        //         """)) {
        //     query.setParameters(component);
        //     query.getFetchPlan().setGroup(Vulnerability.FetchGroup.METRICS_UPDATE.name());
        //     return List.copyOf((List<Vulnerability>) query.executeList());
        // }
>>>>>>> d62e5118 (WIP fetching)
    }

    private static long getTotalAuditedFindings(final PersistenceManager pm, final Component component) throws Exception {
        LOGGER.debug("Getting total audited findings for component " + component.getUuid());
        return component.getAnalysises().stream()
                    .filter(a -> 
                        !a.isSuppressed() && 
                        a.getAnalysisState() != AnalysisState.NOT_SET &&
                        a.getAnalysisState() != AnalysisState.IN_TRIAGE).count();
        // try (final Query<Analysis> query = pm.newQuery(Analysis.class)) {
        //     query.setFilter("""
        //             component == :component &&
        //             suppressed == false &&
        //             analysisState != :notSet &&
        //             analysisState != :inTriage
        //             """);
        //     query.setParameters(component, AnalysisState.NOT_SET, AnalysisState.IN_TRIAGE);
        //     query.setResult("count(this)");
        //     return query.executeResultUnique(Long.class);
        // }
    }

    private static long getTotalSuppressedFindings(final PersistenceManager pm, final Component component) throws Exception {
        LOGGER.debug("Getting total suppressed findings for component " + component.getUuid());
        return component.getAnalysises().stream().filter(a -> a.isSuppressed()).count();
        // try (final Query<Analysis> query = pm.newQuery(Analysis.class)) {
        //     query.setFilter("component == :component && suppressed == true");
        //     query.setParameters(component);
        //     query.setResult("count(this)");
        //     return query.executeResultUnique(Long.class);
        // }
    }

    private static List<PolicyViolation> getPolicyViolations(final PersistenceManager pm, final Component component) throws Exception {
        LOGGER.debug("Getting policy violations for component " + component.getUuid());
        return component.getPolicyViolations().stream().filter(pv -> pv.getAnalysis() == null || !pv.getAnalysis().isSuppressed()).toList();
        // try (final Query<PolicyViolation> query = pm.newQuery(PolicyViolation.class)) {
        //     query.setFilter("component == :component && (analysis == null || analysis.suppressed == false)");
        //     query.setParameters(component);
        //     query.setResult("type, policyCondition.policy.violationState");
        //     return List.copyOf(query.executeResultList(PolicyViolationProjection.class));
        // }
    }

    private static long getTotalAuditedPolicyViolations(final PersistenceManager pm, final Component component, final PolicyViolation.Type violationType) throws Exception {
        LOGGER.debug("Getting total audited policy violations for component " + component.getUuid());
        return component.getPolicyViolations().stream().filter(pv -> pv.getType() == violationType && pv.getAnalysis() != null && !pv.getAnalysis().isSuppressed() && pv.getAnalysis().getAnalysisState() != ViolationAnalysisState.NOT_SET).count();

        // try (final Query<ViolationAnalysis> query = pm.newQuery(ViolationAnalysis.class)) {
        //     query.setFilter("""
        //             component == :component &&
        //             suppressed == false &&
        //             analysisState != :notSet &&
        //             policyViolation.type == :violationType
        //             """);
        //     query.setParameters(component, ViolationAnalysisState.NOT_SET, violationType);
        //     query.setResult("count(this)");
        //     return query.executeResultUnique(Long.class);
        // }
    }

    public record PolicyViolationProjection(Enum<?> type, Enum<?> violationState) {
    }

}

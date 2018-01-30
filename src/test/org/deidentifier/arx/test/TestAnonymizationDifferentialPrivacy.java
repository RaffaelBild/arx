/*
 * ARX: Powerful Data Anonymization
 * Copyright 2012 - 2017 Fabian Prasser, Florian Kohlmayer and contributors
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.deidentifier.arx.test;

import java.util.Arrays;
import java.util.Collection;

import org.deidentifier.arx.ARXConfiguration;
import org.deidentifier.arx.criteria.EDDifferentialPrivacy;
import org.deidentifier.arx.metric.Metric;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 * Tests for differential privacy
 *
 * @author Fabian Prasser
 * @author Florian Kohlmayer
 */
@RunWith(Parameterized.class)
public class TestAnonymizationDifferentialPrivacy extends AbstractAnonymizationTest {

    /**
     * Create tests
     * @return
     */
    @Parameters(name = "{index}:[{0}]")
    public static Collection<Object[]> cases() {
        return Arrays.asList(new Object[][] {
            { new ARXAnonymizationTestCase(createDataDependentConfiguration(Metric.createEntropyMetric(), 2d, 1d, 1E-5d, 10, false), "./data/adult.csv", 0.6684978203609981, new int[] { 1, 4, 0, 1, 2, 2, 1, 1, 0 }, false) },
            { new ARXAnonymizationTestCase(createDataDependentConfiguration(Metric.createEntropyMetric(), 2d, 1d, 1E-5d, 10, false), "./data/cup.csv", 0.3942298849567326, new int[] { 4, 3, 0, 1, 0, 3, 3, 3 }, false) },
            { new ARXAnonymizationTestCase(createDataDependentConfiguration(Metric.createEntropyMetric(), 2d, 1d, 1E-5d, 10, false), "./data/fars.csv", 0.4331241264918216, new int[] { 4, 1, 2, 2, 0, 1, 1, 1 }, false) },
            { new ARXAnonymizationTestCase(createDataDependentConfiguration(Metric.createEntropyMetric(), 2d, 1d, 1E-5d, 10, false), "./data/atus.csv", 0.4798380763190961, new int[] { 1, 4, 0, 1, 1, 1, 1, 1, 1 }, false) },
            { new ARXAnonymizationTestCase(createDataDependentConfiguration(Metric.createEntropyMetric(), 2d, 1d, 1E-5d, 10, false), "./data/ihis.csv", 0.43355679295479355, new int[] { 4, 1, 1, 1, 3, 1, 0, 0, 0 }, false) },
            { new ARXAnonymizationTestCase(createDataDependentConfiguration(Metric.createEntropyMetric(), 1d, 0.1d, 1E-5d, 10, false), "./data/adult.csv", 0.7461734885329702, new int[] { 1, 3, 1, 1, 3, 2, 1, 2, 1 }, false) },
            { new ARXAnonymizationTestCase(createDataDependentConfiguration(Metric.createEntropyMetric(), 1d, 0.1d, 1E-5d, 10, false), "./data/cup.csv", 0.7991394919170811, new int[] { 5, 4, 0, 1, 0, 3, 4, 4 }, false) },
            { new ARXAnonymizationTestCase(createDataDependentConfiguration(Metric.createEntropyMetric(), 1d, 0.1d, 1E-5d, 10, false), "./data/fars.csv", 0.6438315905368939, new int[] { 4, 2, 2, 3, 1, 1, 2, 2 }, false) },
            { new ARXAnonymizationTestCase(createDataDependentConfiguration(Metric.createEntropyMetric(), 2d, 1d, 1E-5d, 100, false), "./data/adult.csv", 0.4766902031326508, new int[] { 0, 3, 0, 1, 2, 1, 2, 1, 1 }, false) },
            { new ARXAnonymizationTestCase(createDataDependentConfiguration(Metric.createEntropyMetric(), 2d, 1d, 1E-5d, 100, false), "./data/cup.csv", 0.5078124514907367, new int[] { 4, 4, 0, 1, 0, 3, 3, 3 }, false) },
            { new ARXAnonymizationTestCase(createDataDependentConfiguration(Metric.createEntropyMetric(), 2d, 1d, 1E-5d, 100, false), "./data/fars.csv", 0.43437306324915353, new int[] { 4, 1, 2, 2, 0, 0, 2, 1 }, false) },
            { new ARXAnonymizationTestCase(createDataDependentConfiguration(Metric.createEntropyMetric(), 1d, 0.1d, 1E-5d, 100, false), "./data/adult.csv", 0.625470682519847, new int[] { 0, 3, 0, 1, 3, 1, 1, 2, 0 }, false) },
            { new ARXAnonymizationTestCase(createDataDependentConfiguration(Metric.createEntropyMetric(), 1d, 0.1d, 1E-5d, 100, false), "./data/cup.csv", 0.5136887308449694, new int[] { 4, 3, 1, 1, 0, 3, 4, 3 }, false) },
            { new ARXAnonymizationTestCase(createDataDependentConfiguration(Metric.createEntropyMetric(), 1d, 0.1d, 1E-5d, 100, false), "./data/fars.csv", 0.44717106212794655, new int[] { 4, 1, 2, 2, 0, 0, 2, 0 }, false) },
        });
    }

    /**
     * Creates a new test case for data-dependent differential privacy.
     * @param metric
     * @param epsilon
     * @param searchBudget
     * @param delta
     * @param steps
     * @return
     */
    private static ARXConfiguration createDataDependentConfiguration(Metric<?> metric, double epsilon, double searchBudget, double delta, int steps, boolean reliable) {
        ARXConfiguration result = ARXConfiguration.create(1d, metric);
        result.addPrivacyModel(new EDDifferentialPrivacy(epsilon, delta, null, true));
        result.setDPSearchBudget(searchBudget);
        result.setDPSearchStepNumber(steps);
        result.setReliableAnonymizationEnabled(reliable);
        return result;
    }

    /**
     * Creates a new instance.
     *
     * @param testCase
     */
    public TestAnonymizationDifferentialPrivacy(final ARXAnonymizationTestCase testCase) {
        super(testCase);
    }

}

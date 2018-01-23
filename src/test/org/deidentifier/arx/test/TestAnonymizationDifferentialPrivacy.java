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
                                              /* Data-dependent differential privacy */
                                              { new ARXAnonymizationTestCase(createDataDependentConfiguration(Metric.createEntropyMetric(), 2d, 1d, 1E-5d, 10, false), "./data/adult.csv", 117891.85842826401, new int[] { 1, 4, 0, 1, 2, 2, 1, 1, 0 }, false) },
                                              { new ARXAnonymizationTestCase(createDataDependentConfiguration(Metric.createEntropyMetric(), 2d, 1d, 1E-5d, 10, false), "./data/cup.csv", 1359829.788416584, new int[] { 4, 3, 0, 1, 0, 3, 3, 3 }, false) },
                                              { new ARXAnonymizationTestCase(createDataDependentConfiguration(Metric.createEntropyMetric(), 2d, 1d, 1E-5d, 10, false), "./data/fars.csv", 955083.3162443438, new int[] { 4, 1, 2, 2, 0, 1, 1, 1 }, false) },
                                              { new ARXAnonymizationTestCase(createDataDependentConfiguration(Metric.createEntropyMetric(), 1d, 0.1d, 1E-5d, 10, false), "./data/adult.csv", 103169.2418849423, new int[] { 1, 3, 1, 1, 3, 2, 1, 2, 1 }, false) },
                                              { new ARXAnonymizationTestCase(createDataDependentConfiguration(Metric.createEntropyMetric(), 1d, 0.1d, 1E-5d, 10, false), "./data/cup.csv", 367975.6391114673, new int[] { 5, 4, 0, 1, 0, 3, 4, 4 }, false) },
                                              { new ARXAnonymizationTestCase(createDataDependentConfiguration(Metric.createEntropyMetric(), 1d, 0.1d, 1E-5d, 10, false), "./data/fars.csv", 630500.0856252835, new int[] { 4, 2, 2, 3, 1, 1, 2, 2 }, false) },
                                              { new ARXAnonymizationTestCase(createDataDependentConfiguration(Metric.createEntropyMetric(), 2d, 1d, 1E-5d, 100, false), "./data/adult.csv", 208972.78334130658, new int[] { 0, 3, 0, 1, 2, 1, 2, 1, 1 }, false) },
                                              { new ARXAnonymizationTestCase(createDataDependentConfiguration(Metric.createEntropyMetric(), 2d, 1d, 1E-5d, 100, false), "./data/cup.csv", 1100085.887215605, new int[] { 4, 4, 0, 1, 0, 3, 3, 3 }, false) },
                                              { new ARXAnonymizationTestCase(createDataDependentConfiguration(Metric.createEntropyMetric(), 2d, 1d, 1E-5d, 100, false), "./data/fars.csv", 975491.0137419946, new int[] { 4, 1, 2, 2, 0, 0, 2, 1 }, false) },
                                              { new ARXAnonymizationTestCase(createDataDependentConfiguration(Metric.createEntropyMetric(), 1d, 0.1d, 1E-5d, 100, false), "./data/adult.csv", 133053.0772066623, new int[] { 0, 3, 0, 1, 3, 1, 1, 2, 0 }, false) },
                                              { new ARXAnonymizationTestCase(createDataDependentConfiguration(Metric.createEntropyMetric(), 1d, 0.1d, 1E-5d, 100, false), "./data/cup.csv", 1039697.2342336713, new int[] { 4, 3, 1, 1, 0, 3, 4, 3 }, false) },
                                              { new ARXAnonymizationTestCase(createDataDependentConfiguration(Metric.createEntropyMetric(), 1d, 0.1d, 1E-5d, 100, false), "./data/fars.csv", 890955.7592430785, new int[] { 4, 1, 2, 2, 0, 0, 2, 0 }, false) },
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

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

import org.apache.commons.math3.analysis.function.Log;
import org.deidentifier.arx.ARXConfiguration;
import org.deidentifier.arx.DataGeneralizationScheme;
import org.deidentifier.arx.DataGeneralizationScheme.GeneralizationDegree;
import org.deidentifier.arx.criteria.DataDependentEDDifferentialPrivacy;
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
    
    /** Constant*/
    private static final double LN3 = new Log().value(3);
    /** Constant*/
    private static final double LN2 = new Log().value(2);
    
    /**
     * Create tests
     * @return
     */
    @Parameters(name = "{index}:[{0}]")
    public static Collection<Object[]> cases() {
        return Arrays.asList(new Object[][] {
                                              /* Data-independent differential privacy */
                                              /* 0 */{ new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createLossMetric()).addPrivacyModel(new EDDifferentialPrivacy(2d, 1E-5d, DataGeneralizationScheme.create(GeneralizationDegree.LOW_MEDIUM), true)), "./data/adult.csv", 0.6820705793543056, new int[] { 0, 2, 0, 1, 1, 1, 1, 1, 0 }, false) },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createLossMetric()).addPrivacyModel(new EDDifferentialPrivacy(1.5d, 1E-6d, DataGeneralizationScheme.create(GeneralizationDegree.HIGH), true)), "./data/adult.csv", 0.8112222411559193, new int[] { 1, 3, 1, 2, 2, 2, 2, 2, 1 }, false) },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(0.0d, Metric.createLossMetric()).addPrivacyModel(new EDDifferentialPrivacy(LN2, 1E-7d, DataGeneralizationScheme.create(GeneralizationDegree.LOW_MEDIUM), true)), "./data/adult.csv", 0.7437618217405468, new int[] { 0, 2, 0, 1, 1, 1, 1, 1, 0 }, false) },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(0.0d, Metric.createLossMetric()).addPrivacyModel(new EDDifferentialPrivacy(LN3, 1E-8d, DataGeneralizationScheme.create(GeneralizationDegree.MEDIUM), true)), "./data/adult.csv", 0.6092780386290699, new int[] { 1, 2, 1, 1, 2, 1, 1, 1, 1 }, false) },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createLossMetric()).addPrivacyModel(new EDDifferentialPrivacy(2d, 1E-5d, DataGeneralizationScheme.create(GeneralizationDegree.MEDIUM_HIGH), true)), "./data/adult.csv", 0.5968589299712612, new int[] { 1, 2, 1, 1, 2, 1, 1, 1, 1 }, false) },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createLossMetric()).addPrivacyModel(new EDDifferentialPrivacy(1.5d, 1E-6d, DataGeneralizationScheme.create(GeneralizationDegree.LOW_MEDIUM), true)), "./data/adult.csv", 0.6856395441402736, new int[] { 0, 2, 0, 1, 1, 1, 1, 1, 0 }, false) },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(0.04d, Metric.createLossMetric()).addPrivacyModel(new EDDifferentialPrivacy(LN2, 1E-7d, DataGeneralizationScheme.create(GeneralizationDegree.MEDIUM_HIGH), true)), "./data/cup.csv", 0.8261910998091719, new int[] { 3, 2, 1, 1, 1, 2, 2, 2 }, false) },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(0.04d, Metric.createLossMetric()).addPrivacyModel(new EDDifferentialPrivacy(1.0d, 1E-8d, DataGeneralizationScheme.create(GeneralizationDegree.MEDIUM), true)), "./data/cup.csv", 0.8499906952842589, new int[] { 3, 2, 1, 1, 1, 2, 2, 2 }, false) },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createLossMetric()).addPrivacyModel(new EDDifferentialPrivacy(2d, 1E-5d, DataGeneralizationScheme.create(GeneralizationDegree.LOW_MEDIUM), true)), "./data/cup.csv", 1.0000000000000004, new int[] { 2, 2, 0, 1, 0, 2, 2, 2 }, false) },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(0.0d, Metric.createLossMetric()).addPrivacyModel(new EDDifferentialPrivacy(1.5d, 1E-6d, DataGeneralizationScheme.create(GeneralizationDegree.MEDIUM_HIGH), true)), "./data/cup.csv", 0.7606582708058056, new int[] { 3, 2, 1, 1, 1, 2, 2, 2 }, false) },
                                              /* 10 */{ new ARXAnonymizationTestCase(ARXConfiguration.create(0.04d, Metric.createLossMetric()).addPrivacyModel(new EDDifferentialPrivacy(2d, 1E-7d, DataGeneralizationScheme.create(GeneralizationDegree.LOW_MEDIUM), true)), "./data/cup.csv", 1.0000000000000004, new int[] { 2, 2, 0, 1, 0, 2, 2, 2 }, true) },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createLossMetric()).addPrivacyModel(new EDDifferentialPrivacy(LN3, 1E-8d, DataGeneralizationScheme.create(GeneralizationDegree.MEDIUM), true)), "./data/cup.csv", 0.839519540778112, new int[] { 3, 2, 1, 1, 1, 2, 2, 2 }, true) },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(0.04d, Metric.createLossMetric()).addPrivacyModel(new EDDifferentialPrivacy(2d, 1E-5d, DataGeneralizationScheme.create(GeneralizationDegree.LOW_MEDIUM), true)), "./data/fars.csv", 0.5814200080206713, new int[] { 2, 1, 1, 1, 0, 1, 1, 1 }, false) },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createLossMetric()).addPrivacyModel(new EDDifferentialPrivacy(LN2, 1E-6d, DataGeneralizationScheme.create(GeneralizationDegree.HIGH), true)), "./data/fars.csv", 0.6800577425519756, new int[] { 4, 2, 2, 2, 1, 2, 2, 2 }, false) },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(0.0d, Metric.createLossMetric()).addPrivacyModel(new EDDifferentialPrivacy(1.0d, 1E-7d, DataGeneralizationScheme.create(GeneralizationDegree.LOW_MEDIUM), true)), "./data/fars.csv", 0.5864014933190864, new int[] { 2, 1, 1, 1, 0, 1, 1, 1 }, false) },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(0.0d, Metric.createLossMetric()).addPrivacyModel(new EDDifferentialPrivacy(1.5d, 1E-8d, DataGeneralizationScheme.create(GeneralizationDegree.MEDIUM), true)), "./data/fars.csv", 0.43090885593016726, new int[] { 3, 1, 2, 2, 1, 1, 2, 1 }, false) },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createLossMetric()).addPrivacyModel(new EDDifferentialPrivacy(LN3, 1E-5d, DataGeneralizationScheme.create(GeneralizationDegree.HIGH), true)), "./data/fars.csv", 0.6796862034370221, new int[] { 4, 2, 2, 2, 1, 2, 2, 2 }, true) },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(0.04d, Metric.createLossMetric()).addPrivacyModel(new EDDifferentialPrivacy(1.0d, 1E-6d, DataGeneralizationScheme.create(GeneralizationDegree.MEDIUM_HIGH), true)), "./data/fars.csv", 0.40463191801066123, new int[] { 3, 1, 2, 2, 1, 1, 2, 1 }, false) },
                                              /* Data-dependent differential privacy */
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createAECSMetric()).addPrivacyModel(new DataDependentEDDifferentialPrivacy(1d, 1d, 1E-5d, 10, true)), "./data/adult.csv", 530.7777777777778, new int[] { 0, 3, 0, 2, 3, 2, 2, 1, 1 }, false) },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createLossMetric()).addPrivacyModel(new DataDependentEDDifferentialPrivacy(1d, 1d, 1E-5d, 10, true)), "./data/adult.csv", 0.48741435942666467, new int[] { 0, 3, 0, 1, 3, 1, 2, 1, 1 }, false) },
                                              /* 20 */ { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createPrecisionMetric()).addPrivacyModel(new DataDependentEDDifferentialPrivacy(1d, 1d, 1E-5d, 10, true)), "./data/adult.csv", 0.569794307600462, new int[] { 0, 4, 0, 1, 1, 2, 2, 2, 0 }, false) },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createDiscernabilityMetric()).addPrivacyModel(new DataDependentEDDifferentialPrivacy(1d, 1d, 1E-5d, 10, true)), "./data/adult.csv", 3.1273568E7, new int[] { 0, 3, 1, 1, 2, 2, 2, 2, 1 }, false) },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createEntropyMetric()).addPrivacyModel(new DataDependentEDDifferentialPrivacy(1d, 1d, 1E-5d, 10, true)), "./data/adult.csv", 241066.51086948867, new int[] { 0, 3, 1, 1, 1, 2, 2, 1, 1 }, false) },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createAECSMetric()).addPrivacyModel(new DataDependentEDDifferentialPrivacy(1d, 1d, 1E-5d, 10, true)), "./data/cup.csv", 180.46636771300447, new int[] { 3, 2, 1, 1, 0, 4, 4, 4 }, false) },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createLossMetric()).addPrivacyModel(new DataDependentEDDifferentialPrivacy(1d, 1d, 1E-5d, 10, true)), "./data/cup.csv", 0.4127415857435688, new int[] { 4, 3, 0, 2, 0, 4, 3, 2 }, false) },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createPrecisionMetric()).addPrivacyModel(new DataDependentEDDifferentialPrivacy(1d, 1d, 1E-5d, 10, true)), "./data/cup.csv", 0.5614846312493788, new int[] { 4, 4, 0, 1, 0, 3, 2, 3 }, false) },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createDiscernabilityMetric()).addPrivacyModel(new DataDependentEDDifferentialPrivacy(1d, 1d, 1E-5d, 10, true)), "./data/cup.csv", 5.5339931E7, new int[] { 3, 4, 1, 1, 0, 4, 3, 4 }, false) },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createEntropyMetric()).addPrivacyModel(new DataDependentEDDifferentialPrivacy(1d, 1d, 1E-5d, 10, true)), "./data/cup.csv", 1365112.629181624, new int[] { 4, 3, 0, 1, 0, 3, 2, 3 }, false) },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createAECSMetric()).addPrivacyModel(new DataDependentEDDifferentialPrivacy(1d, 1d, 1E-5d, 10, true)), "./data/fars.csv", 1875.2941176470588, new int[] { 4, 0, 2, 3, 1, 1, 3, 2 }, false) },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createLossMetric()).addPrivacyModel(new DataDependentEDDifferentialPrivacy(1d, 1d, 1E-5d, 10, true)), "./data/fars.csv", 0.3464644015245275, new int[] { 4, 1, 3, 2, 0, 1, 2, 0 }, false) },
                                              /* 30 */ { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createPrecisionMetric()).addPrivacyModel(new DataDependentEDDifferentialPrivacy(1d, 1d, 1E-5d, 10, true)), "./data/fars.csv", 0.5148531602885822, new int[] { 2, 0, 3, 3, 0, 1, 3, 0 }, false) },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createDiscernabilityMetric()).addPrivacyModel(new DataDependentEDDifferentialPrivacy(1d, 1d, 1E-5d, 10, true)), "./data/fars.csv", 1.28885698E8, new int[] { 3, 2, 2, 1, 1, 2, 2, 1 }, false) },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createEntropyMetric()).addPrivacyModel(new DataDependentEDDifferentialPrivacy(1d, 1d, 1E-5d, 10, true)), "./data/fars.csv", 984333.8872676799, new int[] { 4, 0, 2, 2, 0, 2, 2, 1 }, false) },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createClassificationMetric(8, 30163)).addPrivacyModel(new DataDependentEDDifferentialPrivacy(1d, 1d, 1E-5d, 1, true)), "./data/adult.csv", 0.5240858004840367, new int[] { 1, 4, 0, 2, 3, 2, 2, 2, 0 }, false, "salary-class") },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createClassificationMetric(2, 63441)).addPrivacyModel(new DataDependentEDDifferentialPrivacy(1d, 1d, 1E-5d, 1, true)), "./data/cup.csv", 0.6544190665342602, new int[] { 5, 4, 0, 1, 1, 4, 4, 4 }, false, "GENDER") },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createClassificationMetric(5, 100937)).addPrivacyModel(new DataDependentEDDifferentialPrivacy(1d, 1d, 1E-5d, 1, true)), "./data/fars.csv", 0.43821393542506715, new int[] { 5, 2, 3, 3, 1, 0, 3, 1 }, false, "ihispanic") },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createClassificationMetric(8, 30163)).addPrivacyModel(new DataDependentEDDifferentialPrivacy(1d, 1d, 1E-5d, 10, true)), "./data/adult.csv", 0.5118191161356629, new int[] { 0, 3, 1, 2, 2, 2, 2, 2, 0 }, false, "salary-class") },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createClassificationMetric(2, 63441)).addPrivacyModel(new DataDependentEDDifferentialPrivacy(1d, 1d, 1E-5d, 10, true)), "./data/cup.csv", 0.6509985655963809, new int[] { 5, 3, 0, 0, 1, 4, 4, 4 }, false, "GENDER") },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createClassificationMetric(5, 100937)).addPrivacyModel(new DataDependentEDDifferentialPrivacy(1d, 1d, 1E-5d, 10, true)), "./data/fars.csv", 0.410820610876091, new int[] { 5, 1, 3, 3, 1, 0, 3, 1 }, false, "ihispanic") },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createClassificationMetric(8, 30163)).addPrivacyModel(new DataDependentEDDifferentialPrivacy(1d, 1d, 1E-5d, 100, true)), "./data/adult.csv", 0.5118191161356629, new int[] { 0, 3, 1, 2, 2, 2, 2, 2, 0 }, false, "salary-class") },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createClassificationMetric(2, 63441)).addPrivacyModel(new DataDependentEDDifferentialPrivacy(1d, 1d, 1E-5d, 100, true)), "./data/cup.csv", 0.6540722876373323, new int[] { 5, 3, 0, 1, 1, 3, 2, 3 }, false, "GENDER") },
                                              { new ARXAnonymizationTestCase(ARXConfiguration.create(1d, Metric.createClassificationMetric(5, 100937)).addPrivacyModel(new DataDependentEDDifferentialPrivacy(1d, 1d, 1E-5d, 100, true)), "./data/fars.csv", 0.4141989557843011, new int[] { 5, 0, 2, 2, 1, 0, 3, 2 }, false, "ihispanic") },
        });
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

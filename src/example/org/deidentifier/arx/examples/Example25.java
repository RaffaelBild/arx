/*
 * ARX: Powerful Data Anonymization
 * Copyright 2012 - 2018 Fabian Prasser and contributors
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

package org.deidentifier.arx.examples;

import java.io.IOException;
import java.util.Iterator;

import org.deidentifier.arx.ARXAnonymizer;
import org.deidentifier.arx.ARXConfiguration;
import org.deidentifier.arx.ARXLattice.ARXNode;
import org.deidentifier.arx.ARXResult;
import org.deidentifier.arx.AttributeType;
import org.deidentifier.arx.Data;
import org.deidentifier.arx.Data.DefaultData;
import org.deidentifier.arx.DataType;
import org.deidentifier.arx.aggregates.HierarchyBuilderIntervalBased;
import org.deidentifier.arx.aggregates.HierarchyBuilderIntervalBased.Range;
import org.deidentifier.arx.aggregates.HierarchyBuilderRedactionBased;
import org.deidentifier.arx.aggregates.HierarchyBuilderRedactionBased.Order;
import org.deidentifier.arx.criteria.KAnonymity;
import org.deidentifier.arx.metric.v2.__MetricV2;

import cern.colt.Arrays;

/**
 * This class implements an example for using the generalized loss metric with different types of
 * generalization hierarchies.
 *
 * @author Fabian Prasser
 * @author Florian Kohlmayer
 */
public class Example25 extends Example {

    /**
     * Entry point.
     * 
     * @param args
     *            The arguments
     * @throws IOException
     */
    public static void main(String[] args) throws IOException {

        // Define data
        DefaultData data = Data.create();
        data.add("age", "gender", "zipcode");
        data.add("34", "male", "81667");
        data.add("45", "female", "81675");
        data.add("66", "male", "81925");
        data.add("70", "female", "81931");
        data.add("34", "female", "81931");
        data.add("70", "male", "81931");
        data.add("45", "male", "81931");

        // Define hierarchies
        HierarchyBuilderIntervalBased<Long> builder1 = HierarchyBuilderIntervalBased.create(
                                                          DataType.INTEGER,
                                                          new Range<Long>(0l,0l,0l),
                                                          new Range<Long>(99l,99l,99l));
        
        // Define base intervals
        builder1.setAggregateFunction(DataType.INTEGER.createAggregate().createIntervalFunction(true, false));
        builder1.addInterval(0l, 20l);
        builder1.addInterval(20l, 33l);
        
        // Define grouping fanouts
        builder1.getLevel(0).addGroup(2);
        builder1.getLevel(1).addGroup(3);
        
        HierarchyBuilderRedactionBased<?> builder2 = HierarchyBuilderRedactionBased.create(Order.RIGHT_TO_LEFT,
                                                                                           Order.RIGHT_TO_LEFT,
                                                                                           ' ',
                                                                                           '*');
        
        // builder2.setDomainProperties(100000, 10, 5);
        // builder2.setDomainAndAlphabetSize(30000, 10, 5);
        // builder2.setDomainSize(30000, 5);
        builder2.setAlphabetSize(10, 5);

        data.getDefinition().setAttributeType("age", builder1);
        data.getDefinition().setAttributeType("gender", AttributeType.QUASI_IDENTIFYING_ATTRIBUTE);
        data.getDefinition().setAttributeType("zipcode", builder2);

        // Create an instance of the anonymizer
        ARXAnonymizer anonymizer = new ARXAnonymizer();
        ARXConfiguration config = ARXConfiguration.create();
        config.addPrivacyModel(new KAnonymity(3));
        config.setSuppressionLimit(0d);
        config.setQualityModel(__MetricV2.createLossMetric());
        config.setSuppressionAlwaysEnabled(false);
        ARXResult result = anonymizer.anonymize(data, config);

        // Process results
        for (ARXNode[] level : result.getLattice().getLevels()) {
            for (ARXNode node : level) {
                Iterator<String[]> transformed = result.getOutput(node, false).iterator();
                System.out.println("Transformation : "+Arrays.toString(node.getTransformation()));
                System.out.println("InformationLoss: "+node.getHighestScore());
                while (transformed.hasNext()) {
                    System.out.print("   ");
                    System.out.println(Arrays.toString(transformed.next()));
                }
            }
        }
    }
}

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

package org.deidentifier.arx.metric.v2;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.deidentifier.arx.ARXConfiguration;
import org.deidentifier.arx.DataDefinition;
import org.deidentifier.arx.certificate.elements.ElementData;
import org.deidentifier.arx.framework.check.groupify.HashGroupify;
import org.deidentifier.arx.framework.check.groupify.HashGroupifyEntry;
import org.deidentifier.arx.framework.data.Data;
import org.deidentifier.arx.framework.data.DataManager;
import org.deidentifier.arx.framework.data.GeneralizationHierarchy;
import org.deidentifier.arx.framework.lattice.Transformation;
import org.deidentifier.arx.metric.MetricConfiguration;

/**
 * This class provides an implementation of the classification metric, assuming all attributes are QIs
 * 
 * @author Raffael Bild
 */
public class MetricClassification extends AbstractMetricSingleDimensional {

    /** SVUID. */
    private static final long serialVersionUID = -3563082888738318238L;
    
    /** Record wrapper*/
    class RecordWrapper {

        /** Field*/
        private final int[] tuple;
        /** Field*/
        private final int hash;

        /**
         * Constructor
         * @param tuple
         */
        public RecordWrapper(int[] tuple) {
            this.tuple = tuple;
            this.hash = Arrays.hashCode(tuple);
        }

        @Override
        public boolean equals(Object other) {
            return Arrays.equals(this.tuple, ((RecordWrapper)other).tuple);
        }

        @Override
        public int hashCode() {
            return hash;
        }
    }
    
    /** Column index of the class attribute */
    private int   classColumnIndex;

    /** Root values of the generalization hierarchies */
    private int[] rootValues;

    /**
     * Creates a new instance.
     * @param classColumnIndex
     * @param rowCount
     */
    protected MetricClassification(int classColumnIndex, int rowCount) {
        super(false, false, false);
        this.classColumnIndex = classColumnIndex;
        super.setNumTuples((double)rowCount);
    }
    
    @Override
    public ILSingleDimensional createMaxInformationLoss() {
        return new ILSingleDimensional(1d);
    }
    
    @Override
    public ILSingleDimensional createMinInformationLoss() {
        return new ILSingleDimensional(0d);
    }
    
    /**
     * Returns the configuration of this metric.
     *
     * @return
     */
    public MetricConfiguration getConfiguration() {
        return new MetricConfiguration(false, // monotonic
                                       super.getGeneralizationSuppressionFactor(), // gs-factor
                                       false, // precomputed
                                       0.0d, // precomputation threshold
                                       AggregateFunction.SUM // aggregate function
        );
    }
    
    @Override
    public boolean isGSFactorSupported() {
        return false;
    }
    
    @Override
    public boolean isScoreFunctionSupported() {
        return true;
    }

    @Override
    public ElementData render(ARXConfiguration config) {
        ElementData result = new ElementData("Classification");
        return result;
    }

    @Override
    public String toString() {
        return "Classification";
    }

    @Override
    protected ILSingleDimensionalWithBound getInformationLossInternal(final Transformation node, final HashGroupify g) {
        double penalizedCount = getNumTuples() - (double)unpenalizedCount(g);
        return new ILSingleDimensionalWithBound(penalizedCount / getNumTuples(), penalizedCount / getNumTuples());
    }

    @Override
    protected ILSingleDimensionalWithBound getInformationLossInternal(Transformation node, HashGroupifyEntry entry) {
        return null;
    }

    @Override
    protected ILSingleDimensional getLowerBoundInternal(Transformation node) {
        return null;
    }

    @Override
    protected ILSingleDimensional getLowerBoundInternal(Transformation node,
                                                        HashGroupify groupify) {
        return null;
    }
    
    @Override
    public double getScore(final Transformation node, final HashGroupify groupify, int k, int numRecords, int[] rootValues) {
        return (double)unpenalizedCount(groupify) / (double)k;
    }
    
    @Override
    protected void initializeInternal(final DataManager manager,
                                      final DataDefinition definition, 
                                      final Data input, 
                                      final GeneralizationHierarchy[] hierarchies, 
                                      final ARXConfiguration config) {
        
        rootValues = new int[manager.getHierarchies().length];
        for (int i = 0; i < manager.getHierarchies().length; i++) {
            int[] row = manager.getHierarchies()[i].getArray()[0];
            rootValues[i] = row[row.length - 1];
        }
    }
    
    /**
     * Calculates the number of unpenalized records
     * @param g
     * @return
     */
    private int unpenalizedCount(final HashGroupify g) {
        
        Map<RecordWrapper, Map<Integer, Integer>> featuresToClassToCount = new HashMap<>();

        for (HashGroupifyEntry entry = g.getFirstEquivalenceClass(); entry != null; entry = entry.nextOrdered) {

            if (!entry.isNotOutlier) continue;

            int[] record = entry.key;
            int count = entry.count;
            int classValue = record[classColumnIndex];

            int[] features = new int[record.length - 1];
            boolean featuresSuppressed = true;
            for (int i = 0; i < record.length; i++) {
                if (i < classColumnIndex) {
                    features[i] = record[i];
                    if (record[i] != rootValues[i]) featuresSuppressed = false;
                } else if (i > classColumnIndex) {
                    features[i - 1] = record[i];
                    if (record[i] != rootValues[i]) featuresSuppressed = false;
                }
            }

            if (featuresSuppressed) continue;

            RecordWrapper featuresWrapped = new RecordWrapper(features);

            Map<Integer, Integer> classToCount = featuresToClassToCount.get(featuresWrapped);
            if (classToCount == null) {
                classToCount = new HashMap<>();
                classToCount.put(classValue, count);
            } else {
                int classCount = classToCount.containsKey(classValue) ? classToCount.get(classValue) + count : count;
                classToCount.put(classValue, classCount);
            }
            featuresToClassToCount.put(featuresWrapped, classToCount);
        }

        int unpenalizedCount = 0;
        for (Map<Integer, Integer> classToCount : featuresToClassToCount.values()) {
            int maxCount = 0;
            for (int count : classToCount.values()) {
                maxCount = Math.max(maxCount, count);
            }
            unpenalizedCount += maxCount;
        }
        
        return unpenalizedCount;
    }
}

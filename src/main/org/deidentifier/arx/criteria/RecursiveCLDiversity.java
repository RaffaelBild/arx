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

package org.deidentifier.arx.criteria;

import java.util.Arrays;

import org.deidentifier.arx.certificate.elements.ElementData;
import org.deidentifier.arx.framework.check.distribution.Distribution;
import org.deidentifier.arx.framework.check.groupify.HashGroupifyEntry;
import org.deidentifier.arx.framework.lattice.Transformation;
import org.deidentifier.arx.reliability.IntervalArithmeticDouble;
import org.deidentifier.arx.reliability.IntervalArithmeticException;
import org.deidentifier.arx.reliability.IntervalDouble;

/**
 * The recursive-(c,l)-diversity criterion.
 *
 * @author Fabian Prasser
 * @author Florian Kohlmayer
 */
public class RecursiveCLDiversity extends LDiversity{

    /**  SVUID */
    private static final long serialVersionUID = -5893481096346270328L;

    /** The parameter c. */
    private final double c;
    
    /**
     * Creates a new instance of the recursive-(c,l)-diversity criterion as proposed in:
     * Machanavajjhala A, Kifer D, Gehrke J.
     * l-diversity: Privacy beyond k-anonymity.
     * Transactions on Knowledge Discovery from Data (TKDD). 2007;1(1):3.
     *
     * @param attribute
     * @param c
     * @param l
     */
    public RecursiveCLDiversity(String attribute, double c, int l){
        super(attribute, l, false, true);
        this.c = c;
    }
    
    @Override
    public RecursiveCLDiversity clone() {
        return new RecursiveCLDiversity(this.getAttribute(),
                                        this.getC(),
                                        (int)this.getL());
    }

    /**
     * Returns the parameter c.
     *
     * @return
     */
    public double getC() {
        return c;
    }

    @Override
    public boolean isAnonymous(Transformation node, HashGroupifyEntry entry) {

        Distribution d = entry.distributions[index];
        
        // if less than l values are present skip
        if (d.size() < minSize) { return false; }

        // Copy and pack
        int[] buckets = d.getBuckets();
        final int[] frequencyCopy = new int[d.size()];
        int count = 0;
        for (int i = 0; i < buckets.length; i += 2) {
            if (buckets[i] != -1) { // bucket not empty
                frequencyCopy[count++] = buckets[i + 1];
            }
        }

        // Sort - TODO: Top 2/3/4 could be calculated more efficiently
        Arrays.sort(frequencyCopy);
        
        // Compute threshold
        long threshold = 0;
        for (int i = frequencyCopy.length - minSize; i >= 0; i--) { // minSize=(int)l;
            threshold += frequencyCopy[i];
        }

        // Check
        return frequencyCopy[frequencyCopy.length - 1] < (threshold * c);
    }

    @Override
    public boolean isReliablyAnonymous(Transformation node, HashGroupifyEntry entry) {

        try {
            Distribution d = entry.distributions[index];
            
            // if less than l values are present skip
            if (d.size() < minSize) { return false; }
    
            // Copy and pack
            int[] buckets = d.getBuckets();
            final int[] frequencyCopy = new int[d.size()];
            int count = 0;
            for (int i = 0; i < buckets.length; i += 2) {
                if (buckets[i] != -1) { // bucket not empty
                    frequencyCopy[count++] = buckets[i + 1];
                }
            }
    
            // Sort - TODO: Top 2/3/4 could be calculated more efficiently
            Arrays.sort(frequencyCopy);
            
            // Compute threshold
            int threshold = 0;
            for (int i = frequencyCopy.length - minSize; i >= 0; i--) { // minSize=(int)l;
                threshold = Math.addExact(threshold, frequencyCopy[i]);
            }
            
            // Multiply using reliable arithmetic
            IntervalArithmeticDouble ia = new IntervalArithmeticDouble();
            IntervalDouble val0 = ia.createInterval(frequencyCopy[frequencyCopy.length - 1]);
            IntervalDouble val1 = ia.mult(ia.createInterval(threshold), ia.createInterval(c));
    
            // Check
            return ia.lessThan(val0, val1);
            
        // Catch relevant exceptions
        } catch (ArithmeticException | IndexOutOfBoundsException | IntervalArithmeticException e) {
             // Unable to determine reliably if the equivalence class satisfies the privacy model.
             // Return false, assuming conservatively that it does not.
             return false;
        }
    }
    
    @Override
    public boolean isReliableAnonymizationSupported() {
        return true;
    }

    @Override
    public boolean isLocalRecodingSupported() {
        return true;
    }

    @Override
    public ElementData render() {
        ElementData result = new ElementData("Recursive-(c,l)-diversity");
        result.addProperty("Attribute", attribute);
        result.addProperty("Reliable", true);
        result.addProperty("Threshold (l)", this.l);
        result.addProperty("Multiplier (c)", this.c);
        return result;
    }

    @Override
	public String toString() {
		return "recursive-("+c+","+minSize+")-diversity for attribute '"+attribute+"'";
	}
}

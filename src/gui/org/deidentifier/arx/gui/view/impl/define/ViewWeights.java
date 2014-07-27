/*
 * ARX: Efficient, Stable and Optimal Data Anonymization
 * Copyright (C) 2012 - 2014 Florian Kohlmayer, Fabian Prasser
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package org.deidentifier.arx.gui.view.impl.define;

import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.deidentifier.arx.DataDefinition;
import org.deidentifier.arx.DataHandle;
import org.deidentifier.arx.gui.Controller;
import org.deidentifier.arx.gui.model.Model;
import org.deidentifier.arx.gui.model.ModelEvent;
import org.deidentifier.arx.gui.model.ModelEvent.ModelPart;
import org.deidentifier.arx.gui.view.def.IView;
import org.deidentifier.arx.metric.Metric;
import org.deidentifier.arx.metric.MetricNDS;
import org.eclipse.jface.layout.GridDataFactory;
import org.eclipse.jface.layout.GridLayoutFactory;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Group;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Scale;

import de.linearbits.swt.widgets.Knob;
import de.linearbits.swt.widgets.KnobRange;

/**
 * This class allows to define weights for attributes
 * @author Fabian Prasser
 */
public class ViewWeights implements IView {
    
    private static final int MINIMUM = 0;
    private static final int MAXIMUM = 1000;

    private Controller          controller = null;
    private Model               model      = null;
    private Composite           panel      = null;

    private final Scale         slider;
    private final Composite     root;
    private final Group     knobscomposite;
    private final Group     slidercomposite;
    private final Set<String>   attributes = new HashSet<String>();
    private final DecimalFormat format     = new DecimalFormat("0.000");

    /**
     * Creates a new instance
     * @param parent
     * @param controller
     */
    public ViewWeights(final Composite parent, final Controller controller) {

        // Register
        this.controller = controller;
        this.controller.addListener(ModelPart.ATTRIBUTE_TYPE, this);
        this.controller.addListener(ModelPart.MODEL, this);
        this.controller.addListener(ModelPart.INPUT, this);
        
        this.root = new Composite(parent, SWT.NONE);
        this.root.setLayout(GridLayoutFactory.swtDefaults().numColumns(1).margins(3, 3).create());
        
        this.knobscomposite = new Group(root, SWT.NONE);
        this.knobscomposite.setLayoutData(GridDataFactory.fillDefaults().grab(true, false).create());
        this.knobscomposite.setLayout(GridLayoutFactory.swtDefaults().numColumns(1).margins(0, 0).create());
        
        this.slidercomposite = new Group(root, SWT.NONE);
        this.slidercomposite.setLayoutData(GridDataFactory.fillDefaults().grab(true, true).create());
        this.slidercomposite.setLayout(GridLayoutFactory.swtDefaults().numColumns(1).margins(3, 0).create());
        
        Composite flt = new Composite(this.slidercomposite, SWT.NONE);
        flt.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, true, 1, 1));
        flt.setLayout(GridLayoutFactory.fillDefaults().numColumns(4).create());
        
        Label label = new Label(flt, SWT.NONE);
        label.setLayoutData(GridDataFactory.fillDefaults().grab(false, false).align(SWT.LEFT, SWT.CENTER).create());
        label.setText("Suppression");
        
        slider = new Scale(flt, SWT.HORIZONTAL);
        slider.setMinimum(MINIMUM);
        slider.setMaximum(MAXIMUM);
        this.setSuppressionWeight(0.5d);
        slider.setLayoutData(GridDataFactory.fillDefaults()
                                            .grab(true, false)
                                            .create());
        slider.addSelectionListener(new SelectionAdapter(){
            public void widgetSelected(SelectionEvent arg0) {
                if (model != null && model.getInputConfig() != null) {
                    double weight = getSuppressionWeight();
                    model.getInputConfig().setSuppressionWeight(weight);
                    if (model.getInputConfig().getMetric() instanceof MetricNDS) {
                        model.getInputConfig().setMetric(Metric.createNDSMetric(weight));
                    }
                }
            }
        });
        
        Button button = new Button(flt, SWT.PUSH);
        button.setLayoutData(GridDataFactory.fillDefaults().grab(false, false).align(SWT.LEFT, SWT.CENTER).create());
        button.setText("Reset");
        button.addSelectionListener(new SelectionAdapter() {
            public void widgetSelected(SelectionEvent arg0) {
                setSuppressionWeight(0.5d);
                if (model != null && model.getInputConfig() != null) {
                    model.getInputConfig().setSuppressionWeight(0.5d);
                    if (model.getInputConfig().getMetric() instanceof MetricNDS) {
                        model.getInputConfig().setMetric(Metric.createNDSMetric(0.5d));
                    }
                }
            }
        });
        
        Label label2 = new Label(flt, SWT.NONE);
        label2.setLayoutData(GridDataFactory.fillDefaults().grab(false, false).align(SWT.LEFT, SWT.CENTER).create());
        label2.setText("Generalization");
        
        root.pack();
    }

    private void setSuppressionWeight(double d) {
        int value = (int)(MINIMUM + d * (double)(MAXIMUM - MINIMUM));
        slider.setSelection(value);
    }

    private double getSuppressionWeight() {
        return ((double)slider.getSelection() - MINIMUM) / (double)(MAXIMUM - MINIMUM);
    }

    @Override
    public void dispose() {
        controller.removeListener(this);
        root.dispose();
    }

    @Override
    public void reset() {
        root.setRedraw(false);
        if (panel != null) {
            panel.dispose();
            panel = null;
        }
        setSuppressionWeight(0.5d);
        attributes.clear();
        root.setRedraw(true);
    }

    @Override
    public void update(ModelEvent event) {
        if (event.part == ModelPart.MODEL) {
            this.model = (Model)event.data;
            if (model.getInputConfig() != null) {
                this.setSuppressionWeight(this.model.getInputConfig().getSuppressionWeight());
            }
        } 
        if (event.part == ModelPart.MODEL ||
            event.part == ModelPart.INPUT) {
            this.attributes.clear();
        } 
        
        if (event.part == ModelPart.ATTRIBUTE_TYPE ||
            event.part == ModelPart.MODEL) {
            if (model!=null) {
                
                // Create ordered list of QIs
                DataDefinition definition = model.getInputDefinition();
                List<String> qis = new ArrayList<String>();
                
                if (definition != null) {
                    Set<String> _qis = definition.getQuasiIdentifyingAttributes();
                    
                    // Break if nothing has changed
                    if (this.attributes.equals(_qis)) {
                        return;
                    }
                    
                    DataHandle handle = model.getInputConfig().getInput().getHandle();
                    for (int i=0; i<handle.getNumColumns(); i++){
                        String attr = handle.getAttributeName(i);
                        if (_qis.contains(attr)){
                            qis.add(attr);
                        }
                    }
                    attributes.clear();
                    attributes.addAll(qis);
                }

                root.setRedraw(false);
                
                // Dispose widgets
                if (panel != null) {
                    panel.dispose();
                }
                
                // Create layout
                panel = new Composite(knobscomposite, SWT.NONE);
                panel.setLayoutData(GridDataFactory.swtDefaults().grab(true, true).align(SWT.FILL, SWT.CENTER).create());
                panel.setLayout(GridLayoutFactory.swtDefaults().numColumns(qis.size()).margins(0, 0).equalWidth(true).create());
                
                // Create composites
                List<Composite> composites = new ArrayList<Composite>();
                for(int i=0; i<qis.size(); i++){
                    Composite c = new Composite(panel, SWT.NONE);
                    c.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, false, 1, 1));
                    c.setLayout(GridLayoutFactory.swtDefaults().numColumns(1).margins(2, 0).create());
                    composites.add(c);
                }
                
                // Create labels
                for(int i=0; i<qis.size(); i++){
                    Label label = new Label(composites.get(i), SWT.CENTER);
                    label.setText(qis.get(i));
                    label.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, false, 1, 1));
                }
                
                // Create knob widgets
                List<Knob<Double>> knobs = new ArrayList<Knob<Double>>();
                for(int i=0; i<qis.size(); i++){
                    Knob<Double> knob = new Knob<Double>(composites.get(i), SWT.NULL, new KnobRange.Double(0d, 1d));
                    knob.setLayoutData(GridDataFactory.swtDefaults().grab(false, false).align(SWT.CENTER, SWT.CENTER).hint(30, 30).create());
                    knobs.add(knob);
                }

                // Create labels
                for(int i=0; i<qis.size(); i++){
                    
                    final Label label = new Label(composites.get(i), SWT.CENTER);
                    label.setText("0.0");
                    label.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, false, 1, 1));
                    
                    final String attribute = qis.get(i);
                    final Knob<Double> knob = knobs.get(i);
                    knob.addSelectionListener(new SelectionAdapter(){
                        public void widgetSelected(SelectionEvent arg0) {
                            double value = knob.getValue();
                            label.setText(format.format(value));
                            if (model != null && model.getInputConfig() != null) {
                                model.getInputConfig().setAttributeWeight(attribute, value);
                            }
                        }
                    });
                }
                
                // Set values
                for(int i=0; i<qis.size(); i++){
                    if (model != null && model.getInputConfig() != null) {
                        knobs.get(i).setValue(model.getInputConfig().getAttributeWeight(qis.get(i)));
                    }
                }
                
                knobscomposite.setVisible(!qis.isEmpty());
                slidercomposite.setVisible(!qis.isEmpty());
                
                root.layout(true, true);    
                root.setRedraw(true);
            }
        }
    }
}
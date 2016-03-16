//
//  UserInterfaceWindow.java
//  455 Cryptogaphy Project
//
//  Created by Joseph Kalash on 1/12/14.
//  Copyright (c) 2014 Joseph Kalash. All rights reserved.
//

import java.awt.*;
import javax.swing.*;
import java.util.Vector;
import java.util.Enumeration;

public class UserInterfaceWindow extends JFrame
{
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	// Set up constants for width and height of frame 
    static final int WIDTH = 800; 
    static final int HEIGHT = 500; 
  
    private JTextField voterIdField;
    private JPasswordField passwordField;
    private JButton submitVoterIdButton;
    private ButtonGroup candidateGroup;
    private JPanel candidatePanel;
    private JButton submitCandidateIdButton;
    private JTextArea resultsArea;
    private JButton verifyVoteButton;
    private JButton voteResultsButton;
    private JButton logoutButton;

    // Accessing methods for the components of the window.
    public JButton getSubmitVoterIdButton() { return submitVoterIdButton; }
    public JButton getSubmitCandidateIdButton() { return submitCandidateIdButton; }
    public JButton getVerifyVoteButton() { return verifyVoteButton; }
    public JButton getVoteResultsButton() { return voteResultsButton; }    
    public JButton getLogoutButton() { return logoutButton; }
    public JTextArea getResultsArea() { return resultsArea; }
    
    // Accessing methods for user data.
    /** Method for retrieving the VoterId from the User Interface
     *
     * @return String containing VoterId
     */
    public String getVoterId() { return voterIdField.getText(); }

    /** Method for retrieving the Password from the User Interface
     *
     * @return String containing Password
     */
    public String getPassword() { return new String(passwordField.getPassword()); }

    /** Method for retrieving the selected candidate from the User Interface
     *
     * @return String containing candidate name
     */
    public String getCandidateId()
    {
        Enumeration<?> enumButtons = candidateGroup.getElements();
        JRadioButton currentRadioButton;
        String selectedCandidateId = null;
        while (enumButtons.hasMoreElements())
        {
            if ( (currentRadioButton = (JRadioButton)enumButtons.nextElement()).isSelected() )
            {
                selectedCandidateId = currentRadioButton.getText();
            }
        }
        return selectedCandidateId;
    }    

    public UserInterfaceWindow()
    {
        super("Virtual Election Booth");
    
        JLabel voterIdLabel = new JLabel("Enter your VoterId below (Case Sensitive):");
        voterIdField = new JTextField();
        JLabel passwordLabel = new JLabel("Enter your Password below (Case Sensitive):");
        passwordField = new JPasswordField();
        submitVoterIdButton = new JButton("Click to Submit VoterId and Password to CLA");
        
        candidateGroup = new ButtonGroup();
        candidatePanel = new JPanel();
    
        submitCandidateIdButton = new JButton("Click to submit your vote");
    
        resultsArea = new JTextArea();
        resultsArea.setLineWrap(true);
        
        verifyVoteButton = new JButton("Click here to verify if your vote has been tallied");
    
        voteResultsButton = new JButton("Click here to view up to date election results");
    
        logoutButton = new JButton("Click here to clear all fields and logout");
        
        GridBagLayout layout = new GridBagLayout(); 
        GridBagConstraints layoutCons = new GridBagConstraints(); 
    
        getContentPane().setLayout(layout);
        
        layoutCons.gridx = 0; 
        layoutCons.gridy = 0; 
        layoutCons.gridwidth = 20; 
        layoutCons.gridheight = 1; 
        layoutCons.fill = GridBagConstraints.HORIZONTAL; 
        layoutCons.insets = new Insets(3, 3, 3, 3); 
        layoutCons.anchor = GridBagConstraints.NORTH; 
        layoutCons.weightx = 1.0; 
        layoutCons.weighty = 0.0; 
        layout.setConstraints(voterIdLabel, layoutCons); 
        getContentPane().add(voterIdLabel);

        layoutCons.gridx = 0; 
        layoutCons.gridy = 1; 
        layoutCons.gridwidth = 20; 
        layoutCons.gridheight = 1; 
        layoutCons.fill = GridBagConstraints.HORIZONTAL; 
        layoutCons.insets = new Insets(3, 3, 3, 3); 
        layoutCons.anchor = GridBagConstraints.NORTH; 
        layoutCons.weightx = 1.0; 
        layoutCons.weighty = 0.0; 
        layout.setConstraints(voterIdField, layoutCons); 
        getContentPane().add(voterIdField);

        layoutCons.gridx = 0; 
        layoutCons.gridy = 2; 
        layoutCons.gridwidth = 20; 
        layoutCons.gridheight = 1; 
        layoutCons.fill = GridBagConstraints.HORIZONTAL; 
        layoutCons.insets = new Insets(3, 3, 3, 3); 
        layoutCons.anchor = GridBagConstraints.NORTH; 
        layoutCons.weightx = 1.0; 
        layoutCons.weighty = 0.0; 
        layout.setConstraints(passwordLabel, layoutCons); 
        getContentPane().add(passwordLabel);

        layoutCons.gridx = 0; 
        layoutCons.gridy = 3; 
        layoutCons.gridwidth = 20; 
        layoutCons.gridheight = 1; 
        layoutCons.fill = GridBagConstraints.HORIZONTAL; 
        layoutCons.insets = new Insets(3, 3, 3, 3); 
        layoutCons.anchor = GridBagConstraints.NORTH; 
        layoutCons.weightx = 1.0; 
        layoutCons.weighty = 0.0; 
        layout.setConstraints(passwordField, layoutCons); 
        getContentPane().add(passwordField);        
    
        layoutCons.gridx = 0; 
        layoutCons.gridy = 4; 
        layoutCons.gridwidth = 20; 
        layoutCons.gridheight = 1; 
        layoutCons.fill = GridBagConstraints.HORIZONTAL; 
        layoutCons.insets = new Insets(3, 3, 3, 3); 
        layoutCons.anchor = GridBagConstraints.NORTH; 
        layoutCons.weightx = 1.0; 
        layoutCons.weighty = 0.0; 
        layout.setConstraints(submitVoterIdButton, layoutCons); 
        getContentPane().add(submitVoterIdButton);

        JScrollPane scrollPane = new JScrollPane(resultsArea);
        layoutCons.gridx = 0; 
        layoutCons.gridy = 5; 
        layoutCons.gridwidth = 20; 
        layoutCons.gridheight = 11; 
        layoutCons.fill = GridBagConstraints.BOTH; 
        layoutCons.insets = new Insets(3, 3, 3, 3); 
        layoutCons.anchor = GridBagConstraints.NORTH; 
        layoutCons.weightx = 1.0; 
        layoutCons.weighty = 1.0; 
        layout.setConstraints(scrollPane, layoutCons); 
        getContentPane().add(scrollPane);
    
        layoutCons.gridx = 20; 
        layoutCons.gridy = 0; 
        layoutCons.gridwidth = 15; 
        layoutCons.gridheight = 8; 
        layoutCons.fill = GridBagConstraints.BOTH; 
        layoutCons.insets = new Insets(3, 3, 3, 3); 
        layoutCons.anchor = GridBagConstraints.NORTH; 
        layoutCons.weightx = 1.0; 
        layoutCons.weighty = 1.0; 
        layout.setConstraints(candidatePanel, layoutCons); 
        getContentPane().add(candidatePanel);
    
        layoutCons.gridx = 20; 
        layoutCons.gridy = 8; 
        layoutCons.gridwidth = 15; 
        layoutCons.gridheight = 2; 
        layoutCons.fill = GridBagConstraints.HORIZONTAL; 
        layoutCons.insets = new Insets(3, 3, 3, 3); 
        layoutCons.anchor = GridBagConstraints.NORTH; 
        layoutCons.weightx = 1.0; 
        layoutCons.weighty = 0.0; 
        layout.setConstraints(submitCandidateIdButton, layoutCons); 
        getContentPane().add(submitCandidateIdButton);
        
        layoutCons.gridx = 20; 
        layoutCons.gridy = 10; 
        layoutCons.gridwidth = 15; 
        layoutCons.gridheight = 2; 
        layoutCons.fill = GridBagConstraints.HORIZONTAL; 
        layoutCons.insets = new Insets(3, 3, 3, 3); 
        layoutCons.anchor = GridBagConstraints.NORTH; 
        layoutCons.weightx = 1.0; 
        layoutCons.weighty = 0.0; 
        layout.setConstraints(verifyVoteButton, layoutCons); 
        getContentPane().add(verifyVoteButton);
        
        layoutCons.gridx = 20; 
        layoutCons.gridy = 12; 
        layoutCons.gridwidth = 15; 
        layoutCons.gridheight = 2; 
        layoutCons.fill = GridBagConstraints.HORIZONTAL; 
        layoutCons.insets = new Insets(3, 3, 3, 3); 
        layoutCons.anchor = GridBagConstraints.NORTH; 
        layoutCons.weightx = 1.0; 
        layoutCons.weighty = 0.0; 
        layout.setConstraints(voteResultsButton, layoutCons); 
        getContentPane().add(voteResultsButton);

        layoutCons.gridx = 20; 
        layoutCons.gridy = 14; 
        layoutCons.gridwidth = 15; 
        layoutCons.gridheight = 2; 
        layoutCons.fill = GridBagConstraints.HORIZONTAL; 
        layoutCons.insets = new Insets(3, 3, 3, 3); 
        layoutCons.anchor = GridBagConstraints.NORTH; 
        layoutCons.weightx = 1.0; 
        layoutCons.weighty = 0.0; 
        layout.setConstraints(logoutButton, layoutCons); 
        getContentPane().add(logoutButton);

        setSize(WIDTH, HEIGHT);
        setVisible(true);
    }

    /** Method to reset all User Interface components to their initial value
     */    
    public void reset()
    {
        voterIdField.setText("");
        passwordField.setText("");
        resultsArea.setText("");
        candidatePanel.removeAll();
        candidatePanel.repaint();
    }

    /** Method to display a radio button for each candidate in the given list
     *
     * @param Vector theCandidateNames: Candidate names to be displayed, matching
     * the format of the list maintained by the CTF.
     */        
    public void displayCandidates(Vector<?> theCandidateNames)
    {
        int index = 0;
        candidateGroup = new ButtonGroup();

        GridBagLayout layout = new GridBagLayout(); 
        GridBagConstraints layoutCons = new GridBagConstraints(); 

        candidatePanel.removeAll();
        candidatePanel.setLayout(layout);
        
        for ( index = 0; index < theCandidateNames.size(); index++ )
        {
            JRadioButton nextCandidateButton = new JRadioButton( (String)theCandidateNames.elementAt(index), false );
            
            layoutCons.gridx = 0; 
            layoutCons.gridy = GridBagConstraints.RELATIVE; 
            layoutCons.gridwidth = GridBagConstraints.REMAINDER; 
            layoutCons.gridheight = 1; 
            layoutCons.fill = GridBagConstraints.HORIZONTAL; 
            layoutCons.insets = new Insets(3, 3, 3, 3); 
            layoutCons.anchor = GridBagConstraints.NORTH; 
            layoutCons.weightx = 1.0; 
            layoutCons.weighty = 0.0; 
            layout.setConstraints(nextCandidateButton, layoutCons); 

            
            candidateGroup.add( nextCandidateButton );
            candidatePanel.add( nextCandidateButton );
        }
        candidatePanel.revalidate();
    }    
}
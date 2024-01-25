import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.io.*;

public class ransomwareDetectorMain extends JFrame{
    private JTextArea selectArea;
    private JTextArea resultArea;
    private JButton predictButton;
    private JButton deleteButton;
    private JFileChooser j;

    private ArrayList<String> command;
    ArrayList<String> ransomwareNames;
    public ransomwareDetectorMain() {
        initComponents();
    }

    private void initComponents() {
        selectArea = new JTextArea();
        resultArea = new JTextArea();
        JButton selectButton = new JButton();
        predictButton = new JButton();
        deleteButton = new JButton();
        JScrollPane resultScroller = new JScrollPane(resultArea);
        j = new JFileChooser();
        command = new ArrayList<>();
        ransomwareNames = new ArrayList<>();

        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        setTitle("Ransomware Detector");

        selectArea.setText("Select files to scan");
        resultArea.setText("The results will be showed here");
        selectButton.setText("Select");
        predictButton.setText("Predict");
        deleteButton.setText("Delete");

        selectArea.setEditable(false);
        resultArea.setEditable(false);
        resultArea.setLineWrap(true);
        resultArea.setWrapStyleWord(true);
        predictButton.setEnabled(false);
        deleteButton.setBackground(Color.getHSBColor(50, 100, 77));
        deleteButton.setEnabled(false);
        deleteButton.setVisible(false);
        j.setMultiSelectionEnabled(true);

        selectButton.addActionListener(this::selectButtonActionPerformed);
        predictButton.addActionListener(this::predictButtonActionPerformed);
        deleteButton.addActionListener(this::deleteButtonActionPerformed);

        GroupLayout layout = new GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createSequentialGroup()
                                .addContainerGap()
                                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                        .addGroup(layout.createSequentialGroup()
                                                .addComponent(selectArea, 500, 500, 1500)
                                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                                .addComponent(selectButton, 100, 100, 100))
                                        .addGroup(layout.createSequentialGroup()
                                                .addComponent(resultScroller, 500, 500, 1500)
                                                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                                        .addComponent(predictButton, 100, 100, 100)
                                                        .addComponent(deleteButton, 100, 100, 100))))
                                .addContainerGap(27, Short.MAX_VALUE))
        );

        layout.setVerticalGroup(
                layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createSequentialGroup()
                                .addContainerGap()
                                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(selectArea, 50, 50, 150)
                                        .addComponent(selectButton))
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                        .addComponent(resultScroller, 300, 300, 900)
                                        .addGroup(layout.createSequentialGroup()
                                                .addComponent(predictButton)
                                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                                .addComponent(deleteButton, 60, 60, 60)))
                                .addContainerGap(21, Short.MAX_VALUE))
        );
        pack();
    }

    //this method is executed when the select button is pressed
    private void selectButtonActionPerformed(java.awt.event.ActionEvent evt) {
        deleteButton.setEnabled(false);
        deleteButton.setVisible(false);
        int r = j.showDialog(null, "Select"); // We choose the files to scan

        if (r == JFileChooser.APPROVE_OPTION) {
            File[] files = j.getSelectedFiles();
            command.clear();

            // We build the command that we will execute with the selected files names
            String home = System.getProperty("user.home");
            String binDirectory = home + "/.venv/bin/python3"; // INSERT THE LOCATION OF YOUR PYTHON3 BINARY HERE
            command.add(binDirectory);
            command.add("python/5.modelPredictor.py");
            for (File file : files) {
                command.add(file.getAbsolutePath());
            }

            if (command.size() == 3) selectArea.setText("1 file selected");
            else selectArea.setText(command.size()-2 + " files selected");

            predictButton.setEnabled(true);
        }

    }

    //this method is executed when the predict button is pressed
    private void predictButtonActionPerformed(java.awt.event.ActionEvent evt) {
        ransomwareNames.clear();
        StringBuilder builder = new StringBuilder();
        String line;

        ProcessBuilder processBuilder = new ProcessBuilder();
        processBuilder.command(command);

        try {
            // We execute the command using the ProcessBuilder class
            Process process = processBuilder.start();
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            BufferedReader err = new BufferedReader(new InputStreamReader(process.getErrorStream()));

            // We read the output of the process, and we split every line to delete the file's absolute path
            // from the line
            while ((line = in.readLine()) != null) {
                String[] splitting = line.split("/");
                builder.append(splitting[splitting.length - 1]).append("\n");

                // If a file is detected as ransomware, we save the path, so we can delete the file later
                if (splitting[splitting.length - 1].contains("ransomware")) {
                    ransomwareNames.add(line.split(" ")[0].substring(1, line.split(" ")[0].length() - 1));
                }
            }

            // UNCOMMENT THIS SECTION TO SHOW ERRORS IF THE APPLICATION DOESN'T WORK
            //-------------------------------------------------
            /*
            while ((line = err.readLine()) != null) {
                builder.append(line).append("\n");
            }
            */
            //-------------------------------------------------

            // If some ransomwares were detected, we show the option to delete them
            if (!ransomwareNames.isEmpty()) {
                builder.append("\nYou can delete the detected ransomwares with the delete button");
                deleteButton.setVisible(true);
                deleteButton.setEnabled(true);
            }

            process.waitFor();
            in.close();

            resultArea.setText(builder.toString()); // We show the results on the GUI
        }
        catch (Exception e) {
            resultArea.setText(e.getMessage());
        }
    }

    //this method is executed when the delete button is pressed
    private void deleteButtonActionPerformed(java.awt.event.ActionEvent evt) {
        for(String filename : ransomwareNames) {
            try {
                // We delete the ransomwares
                Files.delete(Path.of(filename));
                resultArea.setText("Ransomware files removed");
            }
            catch(Exception e) {
                resultArea.setText(e.toString());
            }
        }
        deleteButton.setEnabled(false);
        deleteButton.setVisible(false);
        predictButton.setEnabled(false);
        selectArea.setText("Select files to scan");
    }

    public static void main(String[] args) {
        java.awt.EventQueue.invokeLater(() -> new ransomwareDetectorMain().setVisible(true));
    }
}

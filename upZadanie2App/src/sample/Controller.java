package sample;

import javafx.fxml.FXML;
import javafx.scene.control.*;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Random;
import java.util.concurrent.TimeUnit;


public class Controller
{
    @FXML
    private TextField pathOfFile;

    @FXML
    private Button encryptBtn;

    @FXML
    private Button decryptBtn;

    @FXML
    private TextArea textOutput;

    private static String key = "";
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/NoPadding";
    private static final String initVector = "encryptionIntVec";
    static SecureRandom rnd = new SecureRandom();
    private static final IvParameterSpec iv = new IvParameterSpec(rnd.generateSeed(16));
    boolean isFileCreated;
    @FXML
    private void initialize()
    {

        textOutput.setStyle("-fx-border-color: black;");
        key = getSaltString();

        try
        {
            File newTextFile = new File("C:\\Users\\masko\\Desktop\\test\\key2.txt");
            isFileCreated = newTextFile.createNewFile();
            System.out.println(isFileCreated);
            if(isFileCreated)
            {
                FileWriter fw = new FileWriter(newTextFile);
                fw.write(key);
                fw.close();
            }

        }
        catch (IOException e)
        {
            //do stuff with exception
            e.printStackTrace();
        }


        encryptBtn.setOnAction(event ->
        {
            System.out.println(pathOfFile.getText());
            File inputFile = new File(pathOfFile.getText());
            System.out.printf("Kluc: %s\n", key);

            System.out.println("Začiatok sifrovania...");
            long start = System.currentTimeMillis();
            encrypt(inputFile);

            System.out.println("Koniec sifrovania...");
            long finish = System.currentTimeMillis();
            long timeElapsed = finish - start;

            String msg = "Čas šifrovania: ";
            textOutput.setText(msg + timeElapsed + "ms \n");

            System.out.printf("Čas šifrovania: %d ms\n\n", +timeElapsed);
        });

        decryptBtn.setOnAction(event ->
        {
            textOutput.clear();
            System.out.println(pathOfFile.getText());
            File inputFile = new File(pathOfFile.getText());
            System.out.printf("Kluc: %s\n", key);

            long start = System.currentTimeMillis();
            System.out.println("Začiatok desifrovania...");
            decrypt(inputFile);

            System.out.println("Koniec desifrovania...");
            long finish = System.currentTimeMillis();
            long timeElapsed = finish - start;

            String msg = "Čas dešifrovania: ";
            textOutput.setText(msg + timeElapsed + "ms \n");

            System.out.printf("Čas desifrovania: %d ms\n", +timeElapsed);
        });
    }

    public static void encrypt(File inputFile)
    {
        File encryptedFile = new File("dummy.encrypted");
        encryptToNewFile(inputFile, encryptedFile);
        //renameToOldFilename(inputFile, encryptedFile);
    }

    public static void decrypt(File inputFile)
    {
        File decryptedFile = new File("dummy_decrypted.txt");
        decryptToNewFile(inputFile, decryptedFile);
        //renameToOldFilename(inputFile, decryptedFile);
    }

    private static void decryptToNewFile(File input, File output) {
        try (FileInputStream inputStream = new FileInputStream(input); FileOutputStream outputStream = new FileOutputStream(output)) {
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

            byte[] buff = new byte[16384];
            for (int readBytes = inputStream.read(buff); readBytes > -1; readBytes = inputStream.read(buff)) {
                outputStream.write(cipher.update(buff, 0, readBytes));
            }
            outputStream.write(cipher.doFinal());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void encryptToNewFile(File inputFile, File outputFile) {
        try (FileInputStream inputStream = new FileInputStream(inputFile); FileOutputStream outputStream = new FileOutputStream(outputFile))
        {
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
            byte[] inputBytes = new byte[8192];
            for (int n = inputStream.read(inputBytes); n > 0; n = inputStream.read(inputBytes))
            {
                byte[] outputBytes = cipher.update(inputBytes, 0, n);
                outputStream.write(outputBytes);
            }
            byte[] outputBytes = cipher.doFinal();
            outputStream.write(outputBytes);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    private static void renameToOldFilename(File oldFile, File newFile)
    {
        if (oldFile.exists()) {
            oldFile.delete();
        }
        newFile.renameTo(oldFile);
    }

    protected String getSaltString() {
        String SALTCHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        StringBuilder salt = new StringBuilder();
        Random rnd = new Random();
        while (salt.length() != 16) { // length of the random string.
            int index = (int) (rnd.nextFloat() * SALTCHARS.length());
            salt.append(SALTCHARS.charAt(index));
        }
        String saltStr = salt.toString();
        return saltStr;

    }
}

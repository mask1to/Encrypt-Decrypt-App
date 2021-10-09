package sample;

import javafx.fxml.FXML;
import javafx.scene.control.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

public class Controller
{
    private static boolean isFileCreated;
    @FXML
    private TextField pathOfFile;

    @FXML
    private Button encryptBtn;

    @FXML
    private Button decryptBtn;

    @FXML
    private TextArea textOutput;

    private static String key = "";
    private static String helper = "";
    private static String name = "momo.encrypted";
    private static String shortcutResult = "";
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/NoPadding";
    //private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    //private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    static SecureRandom rnd = new SecureRandom();
    private static final IvParameterSpec iv = new IvParameterSpec(rnd.generateSeed(16));
    @FXML
    private void initialize()
    {

        textOutput.setStyle("-fx-border-color: black;");
        textOutput.setEditable(false);
        key = getSaltString();

        encryptBtn.setOnAction(event ->
        {
            System.out.println(pathOfFile.getText());
            File inputFile = new File(pathOfFile.getText());
            if(shortcutLength(pathOfFile) == 4)
            {
                shortcutResult = pathOfFile.getText().substring(pathOfFile.getText().length()-4, pathOfFile.getText().length());
            }
            else if(shortcutLength(pathOfFile) == 5)
            {
                shortcutResult = pathOfFile.getText().substring(pathOfFile.getText().length()-5, pathOfFile.getText().length());
            }
            else if(shortcutLength(pathOfFile) == 6)
            {
                shortcutResult = pathOfFile.getText().substring(pathOfFile.getText().length()-6, pathOfFile.getText().length());
            }
            else if(shortcutLength(pathOfFile) == 7)
            {
                shortcutResult = pathOfFile.getText().substring(pathOfFile.getText().length()-7, pathOfFile.getText().length());
            }
            encrypt(inputFile, pathOfFile, textOutput);
        });

        decryptBtn.setOnAction(event ->
        {
            textOutput.clear();
            System.out.println(pathOfFile.getText());
            File inputFile = new File(pathOfFile.getText());
            decrypt(inputFile, pathOfFile, textOutput);
        });
    }

    public static int shortcutLength(TextField pathOfFile)
    {
        helper = pathOfFile.getText().substring(pathOfFile.getText().length()-4, pathOfFile.getText().length());
        if(!helper.contains("."))
        {
            helper = pathOfFile.getText().substring(pathOfFile.getText().length()-5, pathOfFile.getText().length());
            if(!helper.contains("."))
            {
                helper = pathOfFile.getText().substring(pathOfFile.getText().length()-6, pathOfFile.getText().length());
                if(!helper.contains("."))
                {
                    helper = pathOfFile.getText().substring(pathOfFile.getText().length()-7, pathOfFile.getText().length());
                }
            }
        }
        return helper.length();
    }

    public static void encrypt(File inputFile, TextField pathOfFile, TextArea txtOutput)
    {
        name = pathOfFile.getText().substring(0, pathOfFile.getText().indexOf("."));
        File encryptedFile = new File(name+".encrypted");
        encryptToNewFile(inputFile, encryptedFile, txtOutput);
    }

    public static void decrypt(File inputFile, TextField pathOfFile, TextArea txtOutput)
    {
        name = pathOfFile.getText().substring(0, pathOfFile.getText().indexOf("."));
        File decryptedFile = new File("original_"+name+shortcutResult);
        decryptToNewFile(inputFile, decryptedFile, txtOutput);
    }

    private static void decryptToNewFile(File input, File output, TextArea txtArea) {
        try (FileInputStream inputStream = new FileInputStream(input); FileOutputStream outputStream = new FileOutputStream(output)) {
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

            try
            {
                File newTextFile = new File("key.txt");
                isFileCreated = newTextFile.createNewFile();
                System.out.println(isFileCreated);
                if(isFileCreated)
                {
                    FileWriter fw = new FileWriter(newTextFile);
                    fw.write(String.valueOf(secretKey.getEncoded()));
                    fw.close();
                }
            }
            catch (IOException e)
            {
                e.printStackTrace();
            }

            System.out.println("Začiatok desifrovania...");
            long start = System.currentTimeMillis();

            byte[] buff = new byte[16384];
            for (int readBytes = inputStream.read(buff); readBytes > -1; readBytes = inputStream.read(buff)) {
                outputStream.write(cipher.update(buff, 0, readBytes));
            }
            outputStream.write(cipher.doFinal());
            long finish = System.currentTimeMillis();
            long timeElapsed = finish - start;
            System.out.println("Koniec desifrovania...");
            System.out.printf("Čas dešifrovania: %d ms\n\n", +timeElapsed);
            String msg = "Čas dešifrovania: ";
            txtArea.setText(msg + timeElapsed + " ms \n");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void encryptToNewFile(File inputFile, File outputFile, TextArea txtArea) {
        try (FileInputStream inputStream = new FileInputStream(inputFile); FileOutputStream outputStream = new FileOutputStream(outputFile))
        {
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
            System.out.println("SecretKey: "+ secretKey.getEncoded());
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

            try
            {
                File newTextFile = new File("key.txt");
                isFileCreated = newTextFile.createNewFile();
                System.out.println(isFileCreated);
                if(isFileCreated)
                {
                    FileWriter fw = new FileWriter(newTextFile);
                    fw.write(String.valueOf(secretKey.getEncoded()));
                    fw.close();
                }
            }
            catch (IOException e)
            {
                e.printStackTrace();
            }

            System.out.println("Začiatok sifrovania...");
            long start = System.currentTimeMillis();
            byte[] inputBytes = new byte[16384];
            for (int n = inputStream.read(inputBytes); n > 0; n = inputStream.read(inputBytes))
            {
                byte[] outputBytes = cipher.update(inputBytes, 0, n);
                outputStream.write(outputBytes);
            }
            byte[] outputBytes = cipher.doFinal();
            outputStream.write(outputBytes);
            long finish = System.currentTimeMillis();
            long timeElapsed = finish - start;
            System.out.println("Koniec sifrovania...");
            System.out.printf("Čas šifrovania: %d ms\n\n", +timeElapsed);
            String msg = "Čas šifrovania: ";
            txtArea.setText(msg + timeElapsed + " ms \n");
        }
        catch (IllegalBlockSizeException | IOException e)
        {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }
    
    protected String getSaltString()
    {
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

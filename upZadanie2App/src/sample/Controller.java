package sample;

import javafx.fxml.FXML;
import javafx.scene.control.*;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.util.Arrays;
import java.util.Random;

public class Controller
{

    @FXML
    private TextField pathOfFile;

    @FXML
    private TextField pathOfOriginalFile;

    @FXML
    private TextField pathOfDecryptedFile;

    @FXML
    private Button encryptBtn;

    @FXML
    private Button decryptBtn;

    @FXML
    private Button verifyBtn;

    @FXML
    private TextArea textOutput, textOutput2;

    private static boolean isFileCreated, isFileCreated2, areSame;
    private static String key = "";
    private static String helper = "";
    private static String name = "momo.encrypted";
    private static String shortcutResult = "";
    private static final String ALGORITHM = "AES";
    private static KeyPairGenerator keyPairGenerator;
    private static KeyPair keyPair;
    private static PublicKey publicKey;
    private static PrivateKey privateKey;
    private static byte[] encryptedKey, decryptedKey;
    //private static final String TRANSFORMATION = "AES/CBC/NoPadding";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    static SecureRandom rnd = new SecureRandom();
    private static final IvParameterSpec iv = new IvParameterSpec(rnd.generateSeed(16));
    @FXML
    private void initialize() throws NoSuchAlgorithmException {

        textOutput.setStyle("-fx-border-color: black;");
        textOutput.setEditable(false);

        textOutput2.setStyle("-fx-border-color: black;");
        textOutput2.setEditable(false);

        key = getSaltString();
        keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        keyPair = keyPairGenerator.generateKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();

        try
        {
            File publicKeyFile = new File("RSApublickey.bin");
            File privateKeyFile = new File("RSAprivatekey.bin");
            isFileCreated = publicKeyFile.createNewFile();
            isFileCreated2 = privateKeyFile.createNewFile();
            System.out.println(isFileCreated);
            System.out.println(isFileCreated2);
            if(isFileCreated && isFileCreated2)
            {
                FileWriter fw = new FileWriter(publicKeyFile);
                FileWriter fw2 = new FileWriter(privateKeyFile);
                fw.write(String.valueOf(publicKey));
                fw2.write(String.valueOf(privateKey));
                fw.close();
                fw2.close();
            }
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }

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

        verifyBtn.setOnAction(event -> {
            File firstFile = new File(pathOfOriginalFile.getText());
            File secondFile = new File(pathOfDecryptedFile.getText());

            try {
                areSame = verifyContent(firstFile, secondFile);
            } catch (IOException e) {
                e.printStackTrace();
            }
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

    boolean verifyContent(File originalFile, File decryptedFile) throws IOException
    {
        BufferedReader reader1 = new BufferedReader(new FileReader(originalFile));
        BufferedReader reader2 = new BufferedReader(new FileReader(decryptedFile));

        String line1 = reader1.readLine();
        String line2 = reader2.readLine();

        boolean areEqual = true;
        int lineNum = 1;

        while(line1 != null || line2 != null)
        {
            if(line1 == null || line2 == null)
            {
                areEqual = false;
                break;
            }
            else if(!line1.equalsIgnoreCase(line2))
            {
                areEqual = false;
                break;
            }
            line1 = reader1.readLine();
            line2 = reader2.readLine();
            lineNum++;
        }

        if(areEqual)
        {
            textOutput2.setText("Áno");
            reader1.close();
            reader2.close();
            return true;
        }
        textOutput2.setText("Nie");
        reader1.close();
        reader2.close();
        return false;

    }

    private static void decryptToNewFile(File input, File output, TextArea txtArea) {
        try (FileInputStream inputStream = new FileInputStream(input); FileOutputStream outputStream = new FileOutputStream(output)) {
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

            System.out.println("Začiatok desifrovania...");
            int count = 0;
            long start = 0;
            byte[] buff = new byte[256];
            for (int readBytes = inputStream.read(buff); readBytes > -1; readBytes = inputStream.read(buff))
            {
                if(count == 0)
                {
                    System.out.println(buff.toString());
                    try
                    {
                        Cipher cipher1 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                        cipher1.init(Cipher.PRIVATE_KEY, privateKey);
                        decryptedKey = buff;
                        decryptedKey = cipher1.doFinal(encryptedKey);
                        System.out.println(decryptedKey.toString());
                        System.out.println(decryptedKey.length);
                    }
                    catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e)
                    {
                        e.printStackTrace();
                    }
                    buff = new byte[16384];
                    start = System.currentTimeMillis();
                }
                else
                {
                    outputStream.write(cipher.update(buff, 0, readBytes));
                }
                count += 1;
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
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

            try
            {
                File newTextFile = new File("AESkey_original.bin");
                isFileCreated = newTextFile.createNewFile();
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

            //Encrypt the key using RSA public key
            try
            {
                Cipher cipher1 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher1.init(Cipher.PUBLIC_KEY, publicKey);
                encryptedKey = cipher1.doFinal(secretKey.getEncoded());
                System.out.println(encryptedKey.toString());
                System.out.println(encryptedKey.length);
            }
            catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e)
            {
                e.printStackTrace();
            }
            catch (IllegalBlockSizeException e)
            {
                e.printStackTrace();
            }
            catch (BadPaddingException e)
            {
                e.printStackTrace();
            }

            System.out.println("Začiatok sifrovania...");
            long start = System.currentTimeMillis();
            byte[] inputBytes = new byte[16384];
            outputStream.write(encryptedKey);
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

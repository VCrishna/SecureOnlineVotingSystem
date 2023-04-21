import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.time.LocalDateTime;
import java.util.*;
import javax.net.*;
import javax.net.ssl.*;
import javax.crypto.*;



/**
 * @author sai_krishna_varakala
 * @bmail svaraka1@binghamton.edu
 * @course CS558
 * @project Secure_Election_Booth
 * @Serv_Implementation
 */
public class Serv {
    public static void main(String[] args) throws NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, KeyStoreException, UnrecoverableKeyException, KeyManagementException{
        
        // one argument <server_port> - 9496
        int serverPort = Integer.parseInt(args[0]);

        // Server port
        // int serverPort = 9496;

        // Server voterinfo file
        // String voterinfoFile = "voterinfo.txt";

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        
        keyStore.load(new FileInputStream("saikrishna.p12"), "123456".toCharArray());

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        keyManagerFactory.init(keyStore, "123456".toCharArray());

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), null, null);

        SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();

        ServerSocketFactory serverSocketFactory = sslServerSocketFactory;

        ServerSocket serverSocket = serverSocketFactory.createServerSocket(serverPort);
        Socket socket = null;
        System.out.println("Server is running on port " + serverPort);

        while (true) {
            try{
                socket = serverSocket.accept();
                System.out.println("Accepted connection from " + socket.getInetAddress());
                
                // Checking if the symmetric key file exists
                File keyFile = new File("symmetric.key");
                if (keyFile.exists()) {
                    // If the keyFile exists, reading the key from it
                    loadSymmetricKey();
                } else {
                    // If the keyFile doesn't exist, generating a new symmetric key and saving it
                    generateSymmetricKey();
                }
    
                // User authentication variable
                boolean authenticated = false;
    
                while (!authenticated) {
                    // Creating input and output streams for the client socket
                    PrintWriter clientWriter = new PrintWriter(socket.getOutputStream(), true);
                    Scanner clientScanner = new Scanner(socket.getInputStream(), "UTF-8");
                    
                    // reading input from the client
                    String input = clientScanner.nextLine();
    
                    // Separating Username, voter registration number, and password
                    String[] cred=input.split(" ");
    
                    // Authenticating user based on the credentials received
                    boolean auth=authenticateUser(cred[0],cred[1],cred[2]);
    
                    // If authentication is successful then server returns true else false
                    if(auth){
                        clientWriter.println("1");
                        clientWriter.flush();
                        // System.out.println("Authentication Successful");
                        authenticated=true;
                    }
                    else{
                        clientWriter.println("0");
                        // System.out.println("Authentication UnSuccessful. Username or Password is invalid.");
                        // System.out.println("Please try again");
                        clientWriter.flush();
                        authenticated=false;
                    }
                    
                    // If the user is authenticated then we are creating a new thread with the socket and username
                    // We are creating new thread to handle multiple clients
                    // We are sending socket and username as parameters
                    if (authenticated) {
                        new Thread(new ElectionServerHandler(socket,cred[0])).start();
                    }
    
                }
            }catch(Exception e){
                e.getMessage();
                e.printStackTrace();
            }
        }
    }
    
    /* Method used to read Symmetric Key */
    private static SecretKey loadSymmetricKey() throws IOException, ClassNotFoundException {
        FileInputStream fis = new FileInputStream("symmetric.key");
        ObjectInputStream ois = new ObjectInputStream(fis);
        SecretKey secretKey = (SecretKey) ois.readObject();
        ois.close();
        return secretKey;
    }

    /* Method used to generate and save Symmetric Key */
    private static SecretKey generateSymmetricKey() throws NoSuchAlgorithmException, FileNotFoundException, IOException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();

        // Store the key in a file
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream("symmetric.key"));
        objectOutputStream.writeObject(secretKey);
        objectOutputStream.close();

        return secretKey;
    }

    /* Method used to authenticate user based on the credentials received from the user.
     * @params: name, regNum, password
     * returns true if authenticated successfully else false
     */
    private static boolean authenticateUser(String name, String registrationNumber, String password) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // Read the "voterinfo.txt" file
        // "voterinfo.txt" file contains all the user details
        BufferedReader br = new BufferedReader(new FileReader("voterinfo.txt"));
        String line;
        String storedPassword = null;
        while ((line = br.readLine()) != null) {
            String[] fields = line.split(" ");
            if (fields[0].equals(name) && fields[1].equals(registrationNumber)) {
                // Removing "E(K," and ")" from the stored password
                // storedPassword = fields[3].substring(2, fields[3].length() - 2);
                storedPassword = fields[2];
                break;
            }
        }
        br.close();

        // User not found in voterinfo.txt return false
        if (storedPassword == null) {
            return false;
        }

        // Encrypt the received password using the symmetric key
        SecretKey secretKey = loadSymmetricKey();
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        // Encrypt stored password
        // byte[] encryptedStoredPasswordBytes = cipher.doFinal(hexStringToByteArray(storedPassword));
        // String encryptedStoredPassword = new String(encryptedStoredPasswordBytes, StandardCharsets.UTF_8);

        // Encrypt received password
        byte[] encryptedReceivedPasswordBytes = cipher.doFinal(hexStringToByteArray(password));
        String encryptedReceivedPassword = new String(encryptedReceivedPasswordBytes, StandardCharsets.UTF_8);

        // Hashing the encrypted password using SHA-1
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
        byte[] hashedBytes = messageDigest.digest(encryptedReceivedPassword.getBytes());
        String hashedReceivedPassword = Base64.getEncoder().encodeToString(hashedBytes);

        // System.out.println(hashedReceivedPassword);
        
        // System.out.println("encryptedStoredPassword-->  "+encryptedStoredPassword);
        // System.out.println("encryptedReceivedPassword-->  "+encryptedReceivedPassword);

        // String AlicePassword = new String(cipher.doFinal(hexStringToByteArray("1234")), StandardCharsets.UTF_8);
        // System.out.println("AlicePassword-->  "+Base64.getEncoder().encodeToString(messageDigest.digest(AlicePassword.getBytes())));
        // String BobPassword = new String(cipher.doFinal(hexStringToByteArray("5678")), StandardCharsets.UTF_8);
        // System.out.println("BobPassword-->  "+Base64.getEncoder().encodeToString(messageDigest.digest(BobPassword.getBytes())));
        // String TomPassword = new String(cipher.doFinal(hexStringToByteArray("9012")), StandardCharsets.UTF_8);
        // System.out.println("TomPassword-->  "+Base64.getEncoder().encodeToString(messageDigest.digest(TomPassword.getBytes())));

        // return encryptedStoredPassword.equals(encryptedReceivedPassword);
        return storedPassword.equals(hashedReceivedPassword);

    }
    
    private static byte[] hexStringToByteArray(String hexString) {
        int length = hexString.length();
        byte[] byteArray = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            byteArray[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i+1), 16));
        }
        return byteArray;
    }
    
    // We can create new Threads for this class
    public static class ElectionServerHandler implements Runnable {

        private Socket socket;
        String username;

        public ElectionServerHandler(Socket socket, String username) {
            this.socket = socket;
            this.username = username;
        }

        @Override
        public void run() {
            System.out.println("new thread created!");
            try {
                System.out.println("Hello from server!");
                InputStream inputStream = socket.getInputStream();
                OutputStream outputStream = socket.getOutputStream();
                // Scanner scanner = new Scanner(inputStream);

                Scanner clientScanner = new Scanner(socket.getInputStream(), "UTF-8");
                PrintWriter clientWriter = new PrintWriter(socket.getOutputStream(), true);

                while (true) {
                    String command = clientScanner.nextLine();

                    if (command.equals("1")) {
                        // Checking if the history file exists
                        File historyFile = new File("history.txt");
                        // If the file does not exist, then we are creating "history.txt" file
                        // and sending "1" to the server so that voter can continue to vote
                        if (!historyFile.exists()) {
                            try {
                                historyFile.createNewFile();
                                clientWriter.println("1");
                                clientWriter.flush();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                        else{
                            // Checking if the user has already voted
                            try {
                                // Opening the history file if it exists
                                if (historyFile.exists()) {
                                    Scanner historyScanner = new Scanner(historyFile);
                                    boolean voted = false;
                                    while (historyScanner.hasNextLine()) {
                                        String line = historyScanner.nextLine();
                                        // If the line contains the voter's name, they have already voted
                                        if (line.contains(username)) {
                                            voted = true;
                                        }
                                    }
                                    // If voted == true, voter has already voted
                                    // Returning 0 to the client
                                    if (voted) {
                                        clientWriter.println("0");
                                        clientWriter.flush();
                                    }
                                    // If voted == false, voter can vote
                                    // Returning 1 to the client, voting page will be displayed
                                    else{
                                        clientWriter.println("1");
                                        clientWriter.flush();
                                    }
                                    historyScanner.close();
                                }
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                    }

                    // After voter voted, i'm creating a new input format which is sent server
                    /* Sample Command received from client - "V Alice Linda"
                    *   V - Voted
                    *   Alice - Voter
                    *   Linda - Candidate
                    */
                    else if(command.startsWith("V ")){
                        /* Sample Command- "V Alice Linda" */
                        String[] votedData = command.split(" ");
                        
                        String resultString = "";

                        /*
                        *   server updates the result in file result which has the following Format:
                        *   Chris <the total number of votes>
                        *   Linda <the total number of votes>
                        */
                        // Opening the result file to read and write
                        File resultFile = new File("result.txt");
                        // if result file does not exist the we are creating it and initialize vote counts to 0
                        if (!resultFile.exists()) {
                            try {
                                resultFile.createNewFile();
                                FileWriter writer = new FileWriter(resultFile);
                                writer.write("Chris 0\nLinda 0\n");
                                writer.close();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                        
                        // If result file exists, checking if it's empty and initialize with default values if necessary
                        if (resultFile.exists()) {
                            try {
                                BufferedReader reader = new BufferedReader(new FileReader(resultFile));
                                if (reader.readLine() == null) {
                                    FileWriter writer = new FileWriter(resultFile);
                                    writer.write("Chris 0\nLinda 0\n");
                                    writer.close();
                                }
                                reader.close();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }

                        // updating the vote result in resultfile.txt
                        if (resultFile.exists()) {
                            try(RandomAccessFile file = new RandomAccessFile(resultFile, "rw")) {
                                // Reading the contents of the resultfile into a string
                                String line = "";
                                while ((line = file.readLine()) != null) {
                                    resultString += line + "\n";
                                }
                                // Spliting the string by newlines to get each candidate's name and votes count
                                String[] results = resultString.split("\n");
                                
                                // As we have only two candidates so i'm extracting votes directly
                                String[] chris = results[0].split(" ");
                                String[] linda = results[1].split(" ");

                                // If the voter selected Chris, incrementing his vote count
                                if (votedData[2].equals("Chris")) {
                                    chris[1] = Integer.toString(Integer.parseInt(chris[1]) + 1);
                                }

                                // If the voter selected Linda, incrementing her vote count
                                else if (votedData[2].equals("Linda")) {
                                    linda[1] = Integer.toString(Integer.parseInt(linda[1]) + 1);
                                }

                                // Writing the updated results to the resultfile
                                file.seek(0);
                                file.writeBytes(chris[0] + " " + chris[1] + "\n");
                                file.writeBytes(linda[0] + " " + linda[1] + "\n");
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                        
                        /*  The server also adds the name of the voter and the date and time when the
                        *   voter votes to a file history that has the following format (if the file history
                        *   does not exist, then create the file):
                        *
                        *   <voter name> <date and time when the voter votes>
                        */
                        // Open the history file for writing
                        File historyFile = new File("history.txt");
                        if (!historyFile.exists()) {
                            // If the file does not exist, create it
                            try {
                                historyFile.createNewFile();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                        // Write the voter name and date and time to the file
                        try (FileWriter writer = new FileWriter(historyFile, true)) {
                            writer.write(votedData[1] + " " + LocalDateTime.now().toString() + "\n");
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }

                    /* If the user enters “2” (i.e. View election result), then the server checks if the
                        total number of votes is equal to the total number of voters.
                        -> If not, the server sends 0 to the client and the client displays “The result is not available”
                        -> Otherwise, the server sends the client the candidate who wins the election
                           and the number of votes each candidate got. The client then displays the
                           results with the following format:

                            <Candidate’s name> Win
                            Chris <the total number of votes>
                            Linda <the total number of votes>
                    */
                    // Checking if the result is available
                    else if (command.equals("2")) {
                        int totalVotes = 0, chrisVotes = 0, lindaVotes = 0;

                        // Reading the contents of the result file
                        File resultFile = new File("result.txt");
                        if (resultFile.exists()) {
                            try(BufferedReader reader = new BufferedReader(new FileReader(resultFile))) {
                                String line = reader.readLine();
                                while (line != null) {
                                    String[] parts = line.split(" ");

                                    if (parts[0].equals("Chris")) {
                                        chrisVotes = Integer.parseInt(parts[1]);
                                    } 
                                    else if (parts[0].equals("Linda")) {
                                        lindaVotes = Integer.parseInt(parts[1]);
                                    }

                                    totalVotes += Integer.parseInt(parts[1]);
                                    line = reader.readLine();

                                }
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }

                        // Reading the contents of the voterinfo file
                        // reading this file to decide whether voting is completed or not
                        File voterinfoFile = new File("voterinfo.txt");
                        int numVoters = 0;
                        if (voterinfoFile.exists()) {
                            try (BufferedReader reader = new BufferedReader(new FileReader(voterinfoFile))){
                                String line = reader.readLine();
                                while (line != null) {
                                    numVoters++;
                                    line = reader.readLine();
                                }
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }

                        // Checking if the result is available
                        // If total no. of voters is equal to the total votes, then voting is completed else voter's yet to vote
                        // if they are not equal then we are sending 0 to client and client will display "The result is not available"
                        if (numVoters != totalVotes) {
                            clientWriter.println("0");
                            clientWriter.flush();
                        }
                        // If they are equal then we need to determine the winner
                        else {
                            String winner = "";
                            if (chrisVotes > lindaVotes) {
                                winner = "Chris";
                            } else if (lindaVotes > chrisVotes) {
                                winner = "Linda";
                            }
                            // Send the winner and vote counts to the client
                            String wnr = winner + " Win Chris "+ chrisVotes+" Linda "+ lindaVotes;
                            clientWriter.println(wnr);
                            clientWriter.flush();
                            }
                    }
                    
                    // Retrieving vote history of the user
                    else if (command.equals("3")) {
                        String userVoteHistory = null;
                        File historyFile = new File("history.txt");
                        boolean userFound = false;
                        if (historyFile.exists()) {
                            try(Scanner historyScanner = new Scanner(historyFile)) {
                                while (historyScanner.hasNextLine()) {
                                    String line = historyScanner.nextLine();
                                    String[] parts = line.split(" ");
                                    if (parts[0].equals(username)) {
                                        userVoteHistory = line;
                                        if (userVoteHistory !=null) {
                                            clientWriter.println(userVoteHistory);
                                            clientWriter.flush();
                                            userFound=true;
                                        }
                                    }
                                }
                                // clientWriter.println("0");
                                // clientWriter.flush();
                            } catch (FileNotFoundException e) {
                                e.printStackTrace();
                            }
                        }
                        else{
                            clientWriter.println("0");
                            clientWriter.flush();
                        }
                        // If user is not found in the history file, send "0" to the client writer
                        if (!userFound) {
                            clientWriter.println("0");
                            clientWriter.flush();
                        }
                    }
                    // EXIT
                    // Close connection
                    else if (command.equals("4")) {
                        System.out.println("Closing Voting Booth for "+username);
                        System.out.println("Good Bye "+username+"!");
                        break;
                    }
                    // Invalid command
                    else {
                        System.out.println("Invalid command");
                        clientWriter.println("Invalid command");
                        clientWriter.flush();
                    }
                }

                // Closing the socket and all the streams
                inputStream.close();
                outputStream.close();
                socket.close();
            } catch (IOException e) {
                e.getMessage();
                e.printStackTrace();
            }
        }
    }
}
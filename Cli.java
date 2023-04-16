import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Scanner;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * @author sai_krishna_varakala
 * @bmail svaraka1@binghamton.edu
 * @course CS558
 * @project Secure_Election_Booth
 * @Cli_Implementation
 */
public class Cli{
    /**
     * @param args
     */
    public static void main(String[] args) {
        // Server Variable
        String serverDomain = "localhost";
        // String serverDomain = String.valueOf(args[0]);
        
        // Port Variable
        int serverPort = 9496;
        // int serverPort = Integer.parseInt(args[1]);

        String id ="";

        try {
            TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                }
                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                }
            } };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
            Socket socket = sslSocketFactory.createSocket(serverDomain, serverPort);

            System.out.println(socket.isConnected()?"Client Connected to Server --> "+serverDomain+":"+serverPort:"Cilent is not connected to any server. Please try again.");

            InputStream inputStream = socket.getInputStream();
            Scanner scanner = new Scanner(System.in);
            Scanner serverScanner = new Scanner(inputStream);
            PrintWriter writer = new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), "UTF-8"), true);

            // Variable for User Authentication
            boolean authenticated = false;

            // Infinite loop until the User is authenticated
            while (!authenticated) {

                System.out.print("Enter name: ");
                id = scanner.nextLine();

                System.out.print("Enter voter registration number: ");
                String voter_registration_number = scanner.nextLine();

                System.out.print("Enter password: ");
                String password = scanner.nextLine();

                // Sending credentials to server for authentication
                writer.println(id + " "+ voter_registration_number + " " + password);
                writer.flush();

                String response = "";
                if(serverScanner.hasNext()){
                    response=serverScanner.nextLine();
                    System.out.println("Response from server --> "+response);
                }
                // 0 - Invalid name, registration number, or password
                // 1 - Authentication Successful
                if (response.equals("1")) {
                    // System.out.println("Authentication Successful");
                    System.out.println("Welcome "+id+"!");
                    authenticated=true;
                } else if (response.equals("0")){
                    System.out.println("Invalid name, registration number, or password");
                }
            }

            // Send and receive commands from the server
            while (true) {
                System.out.println("Please enter a number(1-3) \n1. Vote \n2. View election result \n3. My vote history \n4. Exit");                
                
                // Reading command
                String command = scanner.nextLine();

                // “1” (Vote)
                if (command.equals("1")) {
                    // Command 1 is sent to the server
                    writer.println(command);
                    writer.flush();
                    String voteResponse = "";
                    if(serverScanner.hasNext()){
                        voteResponse=serverScanner.nextLine();
                        System.out.println("voteResponse from server --> "+voteResponse);
                    }
                    // If response from server is 1 then we display list of candidates for voting
                    if (voteResponse.equals("1")) {
                        System.out.println("Candidates: (enter 1 or 2) \n1. Chris \n2. Linda");
                        // Reading input from user
                        command = scanner.nextLine();
                        // We are appending "V <username> <candidate_name>" to the command
                        // to receive it at the server and update it accordingly
                        command = command.equals("1")?"Chris":"Linda";
                        command = "V "+ id +" "+command;
                        // Command sent to the server (1 or 2)
                        writer.println(command);
                        writer.flush();
                        // command="";
                        System.out.println("Thank You for Voting!!");
                    }else{
                        System.out.println("you have already voted");
                    }
                                        
                }

                // “2” (View election result)
                else if (command.equals("2")) {
                    // Sending command to server
                    writer.println(command);
                    writer.flush();
                    String resultResponse = "";
                    if(serverScanner.hasNext()){
                        resultResponse=serverScanner.nextLine();
                        System.out.println("resultResponse from server --> "+resultResponse);
                    }
                    if (resultResponse.equals("0")) {
                        System.out.println("The result is not available");
                    }
                    else{
                        // Formating received response
                        // System.out.println(resultResponse);
                        /* <Candidate’s name> Win
                            Chris <the total number of votes>
                            Linda <the total number of votes> */
                        String[] responseParts = resultResponse.split(" ");
                        System.out.println(responseParts[0]+" "+responseParts[1]+" \n"+
                                            responseParts[2]+" "+responseParts[3]+" \n"+
                                            responseParts[4]+" "+responseParts[5]);
                    }
                }

                // “3” (My vote history)
                else if(command.equals("3")){
                    // Sending command to server
                    writer.println(command);
                    writer.flush();
                    String voteHistoryResponse = "";
                    if(serverScanner.hasNext()){
                        voteHistoryResponse=serverScanner.nextLine();
                        // System.out.println("voteHistoryResponse from server --> "+voteHistoryResponse);
                    }
                    if (voteHistoryResponse.equals("0")) {
                        System.out.println("You haven't voted yet, please vote");
                    }
                    else{
                        // Format this response accordingly
                        System.out.println(voteHistoryResponse);
                    }
                }
                
                // “4” (Terminates client and server)
                else if (command.equals("4")) {
                    // Sending command to server
                    writer.println(command);
                    writer.flush();
                    System.out.println("Closing Voting Booth");
                    System.out.println("Good Bye!");
                    break;

                }
                else {
                    // Sending command to server
                    writer.println(command);
                    writer.flush();
                    System.out.println("Invalid Command");
                }
            }
            // Closing the socket and all the streams
            socket.close();
            serverScanner.close();
            writer.close();
            scanner.close();
        }catch (Exception e) {
            e.getMessage();
            e.printStackTrace();
        }
    }
}

Sai Krishna Varakala
svaraka1@binghamton.edu
java

Tested on remote.cs.binghamton.edu

To Build the program: make

To execute the program: 
    Server: java Serv 9496
    Client: java Cli remote(XX) 9496

Once Server is running in port 9496, we can connect any number of clients to the server.
remote(XX): remote(0-7) in which server is running
            Ex: remote05
After establishing the connection between client and server we need to authenticate user

User Credentials:
Username    RegistrationNum     Password
Alice           1123456           1234
Bob             1138765           5678
Tom             1154571           9012


After authentication, Main menu will be displayed and user can select any option shown in the menu.

Note: Once election is completed or to start new election please clear contents of "history.txt" and "result.txt"
      Perform this operation before starting new election
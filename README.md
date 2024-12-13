# Overview
Uses the implementation of a secure channel from "Cryptography Engineering" to create communication
between a local websocket. All cryptographic functions are located in "cryptography" while client
and server folders handle the websocket connection and actual sending of messages. 

## To use
1. Clone repo
2. Open up a command prompt
3. Create a python virtual environment and download any necessary libraries. Name this "Client"
4. Create another command prompt, activate virtual environment, and name command prompt "Server". 
5. In "Server" command prompt, cd server and run "python server.py". This opens up Server to listen to the port. 
6. In "Client" command prompt, cd client and run "python client.py". This connects Client to Server port.
7. Type in whatever message, and you will see it pop up on Server command prompt. 
8. Go to Server, and respond with whatever message. You will see it on Client command prompt. 
Done!
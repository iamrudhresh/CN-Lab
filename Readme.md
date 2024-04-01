1.	Write a simple HTTP web client program using TCP sockets to download a web page. Get the URL and pass it for buffering the content and write it as a html file and make it to get downloaded.
```java
import java.io.*;
import java.net.*;

public class SimpleWebClient {
    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Usage: java SimpleWebClient <URL>");
            return;
        }

        String urlString = args[0];
        try {
            URL url = new URL(urlString);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");

            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                StringBuilder response = new StringBuilder();
                String inputLine;

                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                in.close();

                // Writing the response to a HTML file
                String fileName = "downloaded_page.html";
                FileWriter fileWriter = new FileWriter(fileName);
                fileWriter.write(response.toString());
                fileWriter.close();

                System.out.println("Web page content has been downloaded and saved as " + fileName);
            } else {
                System.err.println("Error: HTTP response code " + responseCode);
            }
            connection.disconnect();
        } catch (MalformedURLException e) {
            System.err.println("Invalid URL: " + e.getMessage());
        } catch (IOException e) {
            System.err.println("Error accessing URL: " + e.getMessage());
        }
    }
}
```

Output

For example, if you run the program with the URL https://www.example.com, and if the request is successful, the program will output:
```java
Web page content has been downloaded and saved as downloaded_page.html

```
2. Write a program to implement echo client and echo server using TCP sockets. This client/server pair runs a simple TCP socket program as an Echo Server that allows one/more client to connect to the server.
EchoServer.java
```
import java.io.*;
import java.net.*;

public class EchoServer {
    public static void main(String[] args) {
        final int PORT = 12345;

        try {
            ServerSocket serverSocket = new ServerSocket(PORT);
            System.out.println("Echo Server is listening on port " + PORT);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client connected: " + clientSocket);

                // Handle client connection in a separate thread
                Thread clientThread = new Thread(new ClientHandler(clientSocket));
                clientThread.start();
            }
        } catch (IOException e) {
            System.err.println("Error in server: " + e.getMessage());
        }
    }

    private static class ClientHandler implements Runnable {
        private Socket clientSocket;

        public ClientHandler(Socket socket) {
            this.clientSocket = socket;
        }

        @Override
        public void run() {
            try {
                BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                PrintWriter writer = new PrintWriter(clientSocket.getOutputStream(), true);

                String inputLine;
                while ((inputLine = reader.readLine()) != null) {
                    System.out.println("Received from client: " + inputLine);
                    writer.println(inputLine); // Echo back to client
                }

                reader.close();
                writer.close();
                clientSocket.close();
            } catch (IOException e) {
                System.err.println("Error handling client: " + e.getMessage());
            }
        }
    }
}
```
EchoClient.java:
```java
import java.io.*;
import java.net.*;

public class EchoClient {
    public static void main(String[] args) {
        final String SERVER_ADDRESS = "localhost";
        final int SERVER_PORT = 12345;

        try {
            Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
            System.out.println("Connected to server: " + socket);

            BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);

            String inputLine;
            while ((inputLine = userInput.readLine()) != null) {
                writer.println(inputLine); // Send user input to server

                if (inputLine.equals("exit")) {
                    break; // Exit loop if user types "exit"
                }

                String serverResponse = reader.readLine();
                System.out.println("Server says: " + serverResponse);
            }

            userInput.close();
            reader.close();
            writer.close();
            socket.close();
        } catch (IOException e) {
            System.err.println("Error in client: " + e.getMessage());
        }
    }
}

```

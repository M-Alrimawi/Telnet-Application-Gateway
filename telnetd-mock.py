import socket
import subprocess
import os


def get_all_users():
    return {
        'user1': 'pass',
        'user2': 'pass'
    }


def start_server():
    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Get local machine name
    host = "0.0.0.0"
    port = 23

    # Bind to the port
    server_socket.bind((host, port))

    # Queue up to 5 requests
    server_socket.listen(5)

    print("Server started on {}:{}".format(host, port))
    try:
        while True:
            # Establish a connection
            client_socket, addr = server_socket.accept()

            print("Got a connection from %s" % str(addr))

            # Receive the telnet negotiation and discard it
            client_socket.recv(1024)

            # Send a prompt for username
            client_socket.send('Username: '.encode('utf-8', errors='ignore'))
            username = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()

            # Send a prompt for password
            client_socket.send('Password: '.encode('utf-8', errors='ignore'))
            password = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()

            print(username, password)

            # Authenticate the user
            all_users = get_all_users()
            if username in all_users and all_users[username] == password:
                # Send a personalized welcome message
                client_socket.send('Welcome {}!\n'.format(username).encode('utf-8', errors='ignore'))

                while True:
                    # Send a prompt for command
                    hostname = socket.gethostname()
                    cwd = os.getcwd()
                    prompt = '{}@{}:{}$ '.format(username, hostname, cwd)
                    client_socket.send(prompt.encode('utf-8', errors='ignore'))

                    # Receive command from the client
                    command = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
                    print('Received command from the client: ', command)

                    # Check if the received command is "exit"
                    if command.lower() == 'exit':
                        print('Received "exit" from the client. Closing connection.')
                        break

                    # Execute the command
                    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate()

                    # Send the output back to the client
                    client_socket.send(stdout + stderr)
            else:
                print('Authentication failed. Closing connection.')
                client_socket.send('Authentication failed.\n'.encode('utf-8', errors='ignore'))

            # Close the connection
            client_socket.close()

    except KeyboardInterrupt:
        print('Server stopped.')
        server_socket.close()


if __name__ == "__main__":
    start_server()

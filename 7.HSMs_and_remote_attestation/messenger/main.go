package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	// "github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var unix_socket_name = "/var/run/messenger/unix.sock"

func main() {
	// Use TPM 2.0 simulator
	simulator, err := simulator.Get()
	if err != nil {
		log.Fatalf("failed to initialize simulator: %v", err)
	}
	defer simulator.Close()

	// Clean the UNIX socket afterwards
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		os.Remove(unix_socket_name)
		os.Exit(1)
	}()

	// ## Demo code begins ##
	// Just for testing that TPM works
	data, err := tpm2.GetRandom(simulator, 10)
	if err != nil {
		log.Fatalf("failed to get random data: %v", err)
	}
	hexString := hex.EncodeToString(data)
	fmt.Printf("What is this, a set of random bytes?: %s \n", hexString)
	fmt.Println("Sending it..")

	// See the file message.proto for more about types
	msg := &Message{
		Kind: DataKind_ENCRYPTED_MESSAGE, // 1 means ENCRYPTED_MESSAGE, however, it is not yet..
		Data: data,
	}

	// // Requires you to listen nc -lU /var/run/messenger/unix.sock in other container
	sendData(msg, true)

	// Sample of receiving data
	// msg := readData(true)
	// fmt.Println("Data: ", hex.EncodeToString(msg.Data))

	// Use netcat to send some data
	// echo -n '{"kind":"ENCRYPTED_MESSAGE","data":"NItJsgxRa4pP3Q=="}' | nc -U /var/run/messenger/unix.sock

	// ## Demo code ends ##

	// Remove demo code and uncomment following to receive/sent data with the socket

	// Reader for user input
	// reader := bufio.NewReader(os.Stdin)
	// Program main loop
	// for {
	// 	displayMenu()
	// 	option, _ := reader.ReadString('\n')
	// 	option = strings.TrimSpace(option)

	// 	switch option {
	// 	case "1":
	// 		fmt.Println("Listening for data...")
	// 		data := readData(true)
	// 		fmt.Printf("All the data as string: %s", string(data.Data))
	// 	case "2":
	// 		fmt.Print("Enter your message: ")
	// 		message, _ := reader.ReadString('\n')
	// 		msg := &Message{
	// 			Kind: 1,
	// 			Data: []byte(message),
	// 		}
	// 		sendData(msg, true)
	// 	case "3":
	// 		fmt.Println("Exiting messenger...")
	// 		return
	// 	default:
	// 		fmt.Println("Invalid option. Please try again.")
	// 	}
	// }
}

func displayMenu() {
	fmt.Println("\n--- Super Secure Messenger Menu ---")
	fmt.Println("1. Receive data")
	fmt.Println("2. Send data")
	fmt.Println("3. Exit")
	fmt.Print("Enter your choice: ")
}

func readData(json bool) *Message {
	// Reads the all data from socket and creates Message Struct
	// Socket in `unix_socket_name` should not exist at this point, we remove it now
	// json controls json/byte serialization
	if _, err := os.Stat(unix_socket_name); !os.IsNotExist(err) {
		// File/socket exists, attempt to remove
		log.Printf("Socket in path %s already exists, removing it...\n", unix_socket_name)
		err := os.Remove(unix_socket_name)
		if err != nil {
			log.Fatalf("Failed to remove the socket: %v", err)
		}
		log.Printf("Socket removed.")
	}
	socket, err := net.Listen("unix", unix_socket_name)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := socket.Accept()
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	// Create a buffer for incoming data.
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Got some data, with size of", n)
	// log.Println("Data as bytes: ", buf[:n])
	// log.Println("Data as string: ", string(buf[:n]))

	// Deserialize bytes to Message type
	msg := &Message{}
	err = func() error {
		if json {
			return protojson.Unmarshal(buf[:n], msg)
		}
		return proto.Unmarshal(buf[:n], msg)
	}()
	if err != nil {
		log.Fatalln("Failed to parse message: ", err)
	}
	return msg

}
func sendData(data *Message, json bool) {
	// Dial to unix socket, send data for the first accepted connection
	// There must be someone listing the socket before this function is called
	// E.g. use nc -lU /tmp/messenger.sock when debugging
	// json controls json/byte serialization

	conn, err := net.Dial("unix", unix_socket_name)
	if err != nil {
		log.Printf("Make sure that someone is listening for the socket %s", unix_socket_name)
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
	out, err := func() ([]byte, error) {
		if json {
			return protojson.Marshal(data)
		}
		return proto.Marshal(data)
	}()
	if err != nil {
		log.Fatalln("Failed to encode message:", err)
	}
	_, err = conn.Write(out)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Data sent and connection closed.")
}

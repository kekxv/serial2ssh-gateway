package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.bug.st/serial"
	"golang.org/x/crypto/ssh"
)

// --- Constants ---

const (
	SerialBaudRate = 115200
)

// --- Logging ---

var (
	logMutex sync.Mutex
)

// sendLog prints a log message with timestamp
func sendLog(format string, args ...interface{}) {
	logMutex.Lock()
	defer logMutex.Unlock()
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("[%s] %s\n", time.Now().Format("15:04:05"), msg)
}

// --- Serial & SSH Logic ---

func runGateway(portName string) {
	sendLog("Opening serial port: %s", portName)

	mode := &serial.Mode{
		BaudRate: SerialBaudRate,
		DataBits: 8,
		Parity:   serial.NoParity,
		StopBits: serial.OneStopBit,
	}

	// Open port
	port, err := serial.Open(portName, mode)
	if err != nil {
		sendLog("ERROR: Failed to open serial port: %v", err)
		sendLog("Please check if the port exists and is not in use.")
		return
	}
	defer port.Close()

	sendLog("Serial port opened. Waiting for connections...")

	// Main Loop
	for {
		// Clear screen before sending welcome message
		writeSerial(port, "\x1b[2J\x1b[H") // VT100 clear screen and move cursor to home

		// Welcome Message
		writeSerial(port, "\r\n\r\n========================================\r\n")
		writeSerial(port, "      Serial-to-SSH Gateway v1.0        \r\n")
		writeSerial(port, "========================================\r\n")
		writeSerial(port, "Please enter connection details.\r\n")

		// 1. Get IP
		host, err := prompt(port, "Target Host (e.g. 192.168.1.1:22): ", false)
		if err != nil {
			if err.Error() == "input cancelled" {
				writeSerial(port, "\r\nInput cancelled.\r\n")
			} else {
				writeSerial(port, fmt.Sprintf("Error reading host: %v\r\n", err))
			}
			continue
		}
		if host == "" {
			writeSerial(port, "Host cannot be empty.\r\n")
			continue
		}
		if !strings.Contains(host, ":") {
			host = host + ":22"
		}

		// 2. Get User
		user, err := prompt(port, "Username: ", false)
		if err != nil {
			if err.Error() == "input cancelled" {
				writeSerial(port, "\r\nInput cancelled.\r\n")
			} else {
				writeSerial(port, fmt.Sprintf("Error reading username: %v\r\n", err))
			}
			continue
		}

		// 3. Get Password or Key
		pass, err := prompt(port, "Password (leave empty for Private Key): ", true)
		if err != nil {
			if err.Error() == "input cancelled" {
				writeSerial(port, "\r\nInput cancelled.\r\n")
			} else {
				writeSerial(port, fmt.Sprintf("Error reading password: %v\r\n", err))
			}
			continue
		}

		var authMethods []ssh.AuthMethod
		var authTypeLog string

		if pass != "" {
			// --- Password Mode ---
			authMethods = []ssh.AuthMethod{ssh.Password(pass)}
			authTypeLog = "password"
		} else {
			// --- Private Key Mode ---
			// Ask user for method
			method, err := prompt(port, "Press [Enter] to Paste Key, or type 'f' for File Path: ", false)
			if err != nil {
				if err.Error() == "input cancelled" {
					writeSerial(port, "\r\nInput cancelled.\r\n")
				} else {
					writeSerial(port, fmt.Sprintf("Error reading method: %v\r\n", err))
				}
				continue
			}

			var keyBytes []byte

			if strings.ToLower(strings.TrimSpace(method)) == "f" {
				// File Path Mode
				keyPath, err := prompt(port, "Private Key Path (on server): ", false)
				if err != nil {
					if err.Error() == "input cancelled" {
						writeSerial(port, "\r\nInput cancelled.\r\n")
					} else {
						writeSerial(port, fmt.Sprintf("Error reading key path: %v\r\n", err))
					}
					continue
				}
				if keyPath == "" {
					writeSerial(port, "Key path cannot be empty.\r\n")
					continue
				}
				keyBytes, err = os.ReadFile(keyPath)
				if err != nil {
					writeSerial(port, fmt.Sprintf("Error reading key file: %v\r\n", err))
					continue
				}
			} else {
				// Paste Mode
				writeSerial(port, "Please paste your Private Key now.\r\n")
				writeSerial(port, "(waiting for '-----END ... PRIVATE KEY-----' line)\r\n")
				keyBytes, err = readKeyFromSerial(port)
				if err != nil {
					if err.Error() == "input cancelled" {
						writeSerial(port, "\r\nInput cancelled.\r\n")
					} else {
						writeSerial(port, fmt.Sprintf("Error reading key: %v\r\n", err))
					}
					continue
				}
				writeSerial(port, "\r\nKey received.\r\n")
			}

			// Parse Key (Common logic)
			signer, err := ssh.ParsePrivateKey(keyBytes)
			if err != nil {
				// Check for encryption
				if strings.Contains(err.Error(), "cannot decode") || strings.Contains(err.Error(), "encrypted") || strings.Contains(err.Error(), "passphrase protected") {
					passphrase, err := prompt(port, "Key Passphrase: ", true)
					if err != nil {
						if err.Error() == "input cancelled" {
							writeSerial(port, "\r\nInput cancelled.\r\n")
						} else {
							writeSerial(port, fmt.Sprintf("Error reading passphrase: %v\r\n", err))
						}
						continue
					}
					signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(passphrase))
					if err != nil {
						writeSerial(port, fmt.Sprintf("Failed to parse encrypted key: %v\r\n", err))
						continue
					}
				} else {
					writeSerial(port, fmt.Sprintf("Failed to parse key: %v\r\n", err))
					continue
				}
			}
			authMethods = []ssh.AuthMethod{ssh.PublicKeys(signer)}
			authTypeLog = "private key"
		}

		writeSerial(port, "\r\nConnecting to "+host+"...\r\n")
		sendLog("Initiating connection to %s@%s using %s", user, host, authTypeLog)

		// 4. Connect SSH
		err = connectSSH(port, host, user, authMethods)
		if err != nil {
			writeSerial(port, fmt.Sprintf("\r\nConnection Error: %v\r\n", err))
			sendLog("SSH Connection failed: %v", err)
			time.Sleep(1 * time.Second) // Anti-spam delay
		} else {
			writeSerial(port, "\r\n--- Session Disconnected ---\r\n")
			sendLog("SSH Session finished for %s", host)
		}
	}
}

// FlowControlWriter wraps an io.Writer and limits the write rate
// to avoid overflowing the serial port buffer (since HW flow control is disabled).
type FlowControlWriter struct {
	Target   io.Writer
	BaudRate int
	aborted  int32
}

func (w *FlowControlWriter) Write(p []byte) (int, error) {
	// If already aborted, drop the data immediately
	if atomic.LoadInt32(&w.aborted) == 1 {
		return len(p), nil
	}

	// Write in small chunks to smooth out the traffic
	const chunkSize = 128
	totalWritten := 0

	for i := 0; i < len(p); i += chunkSize {
		// Check for abort signal before each chunk
		if atomic.LoadInt32(&w.aborted) == 1 {
			return len(p), nil
		}

		end := i + chunkSize
		if end > len(p) {
			end = len(p)
		}
		chunk := p[i:end]

		n, err := w.Target.Write(chunk)
		if n > 0 {
			totalWritten += n
			bits := int64(n * 10)
			duration := time.Duration(bits*1000000/int64(w.BaudRate)) * time.Microsecond
			time.Sleep(duration)
		}
		if err != nil {
			return totalWritten, err
		}
	}
	return totalWritten, nil
}

func (w *FlowControlWriter) Abort() {
	atomic.StoreInt32(&w.aborted, 1)
}

func (w *FlowControlWriter) ClearAbort() {
	atomic.StoreInt32(&w.aborted, 0)
}

// InputInterceptor observes serial input to detect Ctrl+C and signal the FlowControlWriter
type InputInterceptor struct {
	Source  io.Reader
	Writer  *FlowControlWriter
	OnPanic func() // Callback to force disconnect

	lastCtrlC  time.Time
	ctrlCCount int
}

func (i *InputInterceptor) Read(p []byte) (n int, err error) {
	n, err = i.Source.Read(p)
	if err != nil {
		return n, err
	}

	for j := 0; j < n; j++ {
		if p[j] == 0x03 { // Ctrl+C
			// Panic detection: 5 times in 2 seconds
			now := time.Now()
			if now.Sub(i.lastCtrlC) < 2*time.Second {
				i.ctrlCCount++
			} else {
				i.ctrlCCount = 1
			}
			i.lastCtrlC = now

			if i.ctrlCCount >= 5 && i.OnPanic != nil {
				i.OnPanic()
			}

			i.Writer.Abort()
			// Auto-clear after a short delay (100ms).
			// This is enough time to "drain" the SSH stdout buffers at CPU speed,
			// but short enough that the subsequent shell prompt won't be missed.
			time.AfterFunc(100*time.Millisecond, func() {
				i.Writer.ClearAbort()
			})
		} else if p[j] != 0x00 {
			// Any other meaningful input also clears the abort flag immediately
			i.Writer.ClearAbort()
			// Reset panic counter on other inputs
			if p[j] != 0x03 {
				i.ctrlCCount = 0
			}
		}
	}
	return n, err
}

func connectSSH(serialPort serial.Port, host, user string, authMethods []ssh.AuthMethod) error {
	config := &ssh.ClientConfig{
		User: user,
		Auth: authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Note: In production, should verify keys
		Timeout:         10 * time.Second,
	}

	client, err := ssh.Dial("tcp", host, config)
	if err != nil {
		return err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	// Request PTY
	modes := ssh.TerminalModes{
		ssh.ECHO:          1, // Enable echo on remote
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
		ssh.CS8:           1, // 8-bit
		ssh.IGNPAR:        1, // Ignore parity
	}

	// Standard VT100/xterm geometry
	if err := session.RequestPty("xterm", 40, 80, modes); err != nil {
		return fmt.Errorf("request for pty failed: %v", err)
	}

	// Bridge streams
	// Use FlowControlWriter for Stdout/Stderr to prevent buffer overrun
	// on the serial port (especially since flow control is disabled).
	// This ensures binary transparency while respecting baud rate.
	fcWriter := &FlowControlWriter{Target: serialPort, BaudRate: SerialBaudRate}
	inputInterceptor := &InputInterceptor{
		Source: serialPort,
		Writer: fcWriter,
		OnPanic: func() {
			sendLog("Panic detected: Multiple Ctrl+C. Force disconnecting session...")
			client.Close()
		},
	}

	session.Stdin = inputInterceptor
	session.Stdout = fcWriter
	session.Stderr = fcWriter

	// Start Shell
	if err := session.Shell(); err != nil {
		return fmt.Errorf("failed to start shell: %v", err)
	}

	sendLog("Session established: %s", host)

	// Notify the serial terminal that the session is ready
	writeSerial(serialPort, "\r\n\x1b[1;32m--- SSH Session Established ---\x1b[0m\r\n")
	writeSerial(serialPort, "\x1b[1;34mTip: If the screen is misaligned, press 'Sync Size' or run 'stty rows 25 cols 80'\x1b[0m\r\n\r\n")

	// Wait for session to end
	return session.Wait()
}

// --- Helper Functions ---

func writeSerial(p io.Writer, msg string) {
	p.Write([]byte(msg))
}

// prompt reads a line from serial, handling backspace and optional masking
func prompt(port io.ReadWriter, question string, mask bool) (string, error) {
	writeSerial(port, question)
	
	var buf []byte
	reader := bufio.NewReader(port)

	for {
		b, err := reader.ReadByte()
		if err != nil {
			return "", err
		}

		// Check for Ctrl+C (ETX - End of Text)
		if b == 0x03 {
			return "", fmt.Errorf("input cancelled")
		}

		// Handle Enter (\r or \n)
		if b == '\r' || b == '\n' {
			writeSerial(port, "\r\n") // Echo newline
			return string(buf), nil
		}

		// Handle Backspace (0x08) or Delete (0x7F)
		if b == 0x08 || b == 0x7F {
			if len(buf) > 0 {
				// Remove last char from buffer
				buf = buf[:len(buf)-1]
				// Erase on terminal: Backspace, Space, Backspace
				writeSerial(port, "\b \b")
			}
			continue
		}

		// Normal character
		buf = append(buf, b)

		if mask {
			writeSerial(port, "*")
		} else {
			writeSerial(port, string(b))
		}
	}
}

// readKeyFromSerial reads lines until it sees the private key footer or detects Ctrl+C
func readKeyFromSerial(port io.ReadWriter) ([]byte, error) {
	reader := bufio.NewReader(port)
	var sb strings.Builder
	var lineBuf strings.Builder

	for {
		b, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}

		// Check for Ctrl+C (ETX - End of Text)
		if b == 0x03 {
			return nil, fmt.Errorf("input cancelled")
		}

		// Accumulate char
		lineBuf.WriteByte(b)

		// Check for line end
		if b == '\n' || b == '\r' {
			line := lineBuf.String()
			sb.WriteString(line)

			// Echo a dot for progress
			writeSerial(port, ".")

			// Check for end of key in the current accumulated line
			if strings.Contains(line, "-----END") && strings.Contains(line, "PRIVATE KEY-----") {
				break
			}

			lineBuf.Reset()
		}
	}
	return []byte(sb.String()), nil
}

func main() {
	portFlag := flag.String("port", "", "Serial port to listen on (e.g., COM1 or /dev/ttyUSB0)")
	listFlag := flag.Bool("list", false, "List available serial ports and exit")
	flag.Parse()

	if *listFlag {
		ports, err := serial.GetPortsList()
		if err != nil {
			log.Fatal(err)
		}
		if len(ports) == 0 {
			fmt.Println("No serial ports found.")
		} else {
			fmt.Println("Available serial ports:")
			for _, p := range ports {
				fmt.Println(" - " + p)
			}
		}
		return
	}

	if *portFlag == "" {
		fmt.Println("Error: Please specify a serial port using -port")
		fmt.Println("Use -list to see available ports.")
		os.Exit(1)
	}

	sendLog("Serial-to-SSH Gateway starting on port %s", *portFlag)
	runGateway(*portFlag)
}

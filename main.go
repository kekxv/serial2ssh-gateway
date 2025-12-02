package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"go.bug.st/serial"
	"golang.org/x/crypto/ssh"
)

// --- Constants ---

const (
	SerialBaudRate = 115200
	MaxLogLines    = 20
)

// --- Types & Models ---

// LogMsg is a message sent from the backend logic to the UI
type LogMsg string

// UI Model
type model struct {
	portName string
	baudRate int
	status   string
	logs     []string
	err      error
	quitting bool
}

// --- Bubble Tea UI Implementation ---

func initialModel(port string) model {
	return model{
		portName: port,
		baudRate: SerialBaudRate,
		status:   "Initializing...",
		logs:     make([]string, 0),
	}
}

func (m model) Init() tea.Cmd {
	// Start the serial gateway logic in a separate goroutine
	return func() tea.Msg {
		runGateway(m.portName)
		return nil
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			m.quitting = true
			return m, tea.Quit
		}
	case LogMsg:
		// Append log and keep it trimmed
		m.logs = append(m.logs, string(msg))
		if len(m.logs) > MaxLogLines {
			m.logs = m.logs[1:]
		}
		// Update status line based on last log if needed, or just keep it separate
		// For now, let's just update the status to "Running" if not set
		if m.status == "Initializing..." {
			m.status = "Running"
		}
		return m, waitForLog() // Wait for next log? 
        // Actually, the channel approach is better handled via a subscription or command.
        // But since we can't easily pass the program reference to the command *after* init without a global or channel,
        // we'll use a global program variable to send messages.
	}
	return m, nil
}

func (m model) View() string {
	if m.quitting {
		return "Shutting down...\n"
	}

	ss := strings.Builder{}
	ss.WriteString(fmt.Sprintf("\n  Serial-to-SSH Gateway (v1.0)\n"))
	ss.WriteString(fmt.Sprintf("  ----------------------------\n"))
	ss.WriteString(fmt.Sprintf("  Port: %s | Baud: %d | Status: %s\n\n", m.portName, m.baudRate, m.status))
	
	ss.WriteString("  --- Logs ---\n")
	for _, l := range m.logs {
		ss.WriteString(fmt.Sprintf("  %s\n", l))
	}
	ss.WriteString("\n  Press Ctrl+C to exit server.\n")
	return ss.String()
}

// --- Global UI Program ---
var p *tea.Program

// sendLog sends a log message to the UI
func sendLog(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if p != nil {
		p.Send(LogMsg(time.Now().Format("15:04:05") + " " + msg))
	}
}

// --- Serial & SSH Logic ---

func runGateway(portName string) {
	sendLog("Opening serial port: %s", portName)

	mode := &serial.Mode{
		BaudRate: SerialBaudRate,
		DataBits: 8,
		Parity:   serial.NoParity,
		StopBits: serial.OneStopBit,
		// Ensure flow control is disabled for Zmodem transparency
	}

	// Open port
	port, err := serial.Open(portName, mode)
	if err != nil {
		sendLog("ERROR: Failed to open serial port: %v", err)
		sendLog("Please check if the port exists and is not in use.")
		return
	}
	defer port.Close()

    // Ensure software flow control is off (library default is usually off, but being explicit if possible is good) 
    // go.bug.st/serial sets basic termios. We assume it's raw enough.
    // Note: The library usually sets raw mode by default.

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
																					} else { // This else belongs to the inner if (encryption check)
																						writeSerial(port, fmt.Sprintf("Failed to parse key: %v\r\n", err))
																						continue
																					}
																				} // This brace closes the 'if err != nil' block for ParsePrivateKey
																				authMethods = []ssh.AuthMethod{ssh.PublicKeys(signer)}
																				authTypeLog = "private key"
																			} // This brace closes the 'else' for (pass != "")				
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
    // Directly using serialPort for Stdin/Stdout/Stderr
    // This ensures binary transparency.
	session.Stdin = serialPort
	session.Stdout = serialPort
	session.Stderr = serialPort

	// Start Shell
	if err := session.Shell(); err != nil {
		return fmt.Errorf("failed to start shell: %v", err)
	}
    
sendLog("Session established: %s", host)

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
        // Filter control characters if strictly text needed? 
        // For password/user, probably safe to accept most printable ascii.
        // We'll just take it.
		buf = append(buf, b)
		
		if mask {
			writeSerial(port, "*")
		} else {
			writeSerial(port, string(b))
		}
	}
}

func waitForLog() tea.Cmd {
    // Placeholder. Actual logging is pushed via global program.
    return nil
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
        // Try to guess? No, safer to ask.
		os.Exit(1)
	}

	m := initialModel(*portFlag)
	p = tea.NewProgram(m)

	if _, err := p.Run(); err != nil {
		fmt.Printf("Alas, there's been an error: %v\n", err)
		os.Exit(1)
	}
}

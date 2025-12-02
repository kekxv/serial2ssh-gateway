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
		// Welcome Message
		writeSerial(port, "\r\n\r\n========================================\r\n")
		writeSerial(port, "      Serial-to-SSH Gateway v1.0        \r\n")
		writeSerial(port, "========================================\r\n")
		writeSerial(port, "Please enter connection details.\r\n")

		// 1. Get IP
	host, err := prompt(port, "Target Host (e.g. 192.168.1.1:22): ", false)
		if err != nil {
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
			continue
		}

		// 3. Get Password
		pass, err := prompt(port, "Password: ", true)
		if err != nil {
			continue
		}

		writeSerial(port, "\r\nConnecting to "+host+"...\r\n")
		sendLog("Initiating connection to %s@%s", user, host)

		// 4. Connect SSH
	err = connectSSH(port, host, user, pass)
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

func connectSSH(serialPort serial.Port, host, user, password string) error {
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
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

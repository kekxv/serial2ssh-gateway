package main

import (
	"bytes"
	"testing"
)

// MockReadWriter helps us simulate a serial port
type MockReadWriter struct {
	Input  *bytes.Buffer // Simulates user typing (Keyboard)
	Output *bytes.Buffer // Simulates what is sent to terminal (Screen)
}

func NewMockRW(input string) *MockReadWriter {
	return &MockReadWriter{
		Input:  bytes.NewBufferString(input),
		Output: &bytes.Buffer{},
	}
}

func (m *MockReadWriter) Read(p []byte) (n int, err error) {
	return m.Input.Read(p)
}

func (m *MockReadWriter) Write(p []byte) (n int, err error) {
	return m.Output.Write(p)
}

func TestPrompt_BasicInput(t *testing.T) {
	// Simulate user typing "192.168.1.1" followed by Enter (\n)
	mock := NewMockRW("192.168.1.1\n")
	
	result, err := prompt(mock, "IP: ", false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Check the returned string (clean logic)
	if result != "192.168.1.1" {
		t.Errorf("Expected '192.168.1.1', got '%s'", result)
	}

	// Check the terminal output (visual logic)
	// Expect: "IP: " (prompt) + "192.168.1.1" (echo) + "\r\n" (newline echo)
	expectedOutput := "IP: 192.168.1.1\r\n"
	if mock.Output.String() != expectedOutput {
		t.Errorf("Expected output %q, got %q", expectedOutput, mock.Output.String())
	}
}

func TestPrompt_CarriageReturn(t *testing.T) {
	// Simulate user typing with \r (common in serial terminals)
	mock := NewMockRW("myuser\r")

	result, err := prompt(mock, "User: ", false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result != "myuser" {
		t.Errorf("Expected 'myuser', got '%s'", result)
	}
}

func TestPrompt_MaskedPassword(t *testing.T) {
	// Simulate user typing "secret"
	mock := NewMockRW("secret\n")

	result, err := prompt(mock, "Password: ", true)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result != "secret" {
		t.Errorf("Expected 'secret', got '%s'", result)
	}

	// Check output: should contain '*' instead of chars
	expectedOutput := "Password: ******\r\n"
	if mock.Output.String() != expectedOutput {
		t.Errorf("Expected output %q, got %q", expectedOutput, mock.Output.String())
	}
}

func TestPrompt_BackspaceLogic(t *testing.T) {
	// Simulate user typing "mistake", then Backspace (0x08), then "e", then Enter
	// Let's try a simpler case: "abc" -> Backspace -> "d" -> Result "abd"
	// Input: 'a', 'b', 'c', 0x08, 'd', '\n'
	
	input := []byte{'a', 'b', 'c', 0x08, 'd', '\n'}
	mock := &MockReadWriter{
		Input:  bytes.NewBuffer(input),
		Output: &bytes.Buffer{},
	}

	result, err := prompt(mock, "Input: ", false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result != "abd" {
		t.Errorf("Expected 'abd', got '%s'", result)
	}

	// Verify Output contains the backspace sequence "\b \b"
	// "Input: " + "a" + "b" + "c" + "\b \b" + "d" + "\r\n"
	outputStr := mock.Output.String()
	
	if !bytes.Contains(mock.Output.Bytes(), []byte("\b \b")) {
		t.Errorf("Expected output to contain backspace sequence, got: %q", outputStr)
	}
}

func TestPrompt_DeleteChar(t *testing.T) {
	// Test 0x7F (DEL)
	input := []byte{'x', 0x7F, 'y', '\n'}
	mock := &MockReadWriter{
		Input:  bytes.NewBuffer(input),
		Output: &bytes.Buffer{},
	}

	result, _ := prompt(mock, "> ", false)
	if result != "y" {
		t.Errorf("Expected 'y', got '%s'", result)
	}
}

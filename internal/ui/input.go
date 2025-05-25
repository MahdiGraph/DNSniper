package ui

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Reader is a helper for reading user input
type Reader struct {
	scanner *bufio.Scanner
}

// NewReader creates a new input reader
func NewReader() *Reader {
	return &Reader{
		scanner: bufio.NewScanner(os.Stdin),
	}
}

// ReadLine reads a line of input
func (r *Reader) ReadLine() string {
	r.scanner.Scan()
	return strings.TrimSpace(r.scanner.Text())
}

// ReadString reads a string with a prompt
func (r *Reader) ReadString(prompt string) string {
	promptColor.Print(prompt)
	return r.ReadLine()
}

// ReadInt reads an integer with a prompt
func (r *Reader) ReadInt(prompt string, min, max, defaultVal int) int {
	for {
		promptColor.Printf("%s [%d-%d, default=%d]: ", prompt, min, max, defaultVal)
		input := r.ReadLine()

		if input == "" {
			return defaultVal
		}

		val, err := strconv.Atoi(input)
		if err != nil || val < min || val > max {
			errorColor.Printf("Please enter a number between %d and %d\n", min, max)
			continue
		}

		return val
	}
}

// ReadBool reads a boolean with a prompt
func (r *Reader) ReadBool(prompt string, defaultVal bool) bool {
	defaultStr := "y/N"
	if defaultVal {
		defaultStr = "Y/n"
	}

	promptColor.Printf("%s [%s]: ", prompt, defaultStr)
	input := strings.ToLower(r.ReadLine())

	if input == "" {
		return defaultVal
	}

	return input == "y" || input == "yes"
}

// ReadOption reads an option from a menu
func (r *Reader) ReadOption(prompt string, options []string) int {
	for i, option := range options {
		fmt.Printf("%d) %s\n", i+1, option)
	}

	for {
		val := r.ReadInt(prompt, 1, len(options), 1)
		return val - 1
	}
}

// ReadIPAddress reads and validates an IP address
func (r *Reader) ReadIPAddress(prompt string) string {
	for {
		promptColor.Print(prompt)
		input := r.ReadLine()

		// Validate IP format
		if input == "" {
			errorColor.Println("IP address cannot be empty.")
			continue
		}

		parts := strings.Split(input, ".")
		if len(parts) != 4 {
			errorColor.Println("Invalid IP address format. Should be X.X.X.X")
			continue
		}

		valid := true
		for _, part := range parts {
			num, err := strconv.Atoi(part)
			if err != nil || num < 0 || num > 255 {
				valid = false
				break
			}
		}

		if !valid {
			errorColor.Println("Invalid IP address. Each part must be between 0-255.")
			continue
		}

		return input
	}
}

// ReadDomain reads and validates a domain name
func (r *Reader) ReadDomain(prompt string) string {
	for {
		promptColor.Print(prompt)
		input := r.ReadLine()

		// Basic domain validation
		if input == "" {
			errorColor.Println("Domain cannot be empty.")
			continue
		}

		if strings.Contains(input, " ") {
			errorColor.Println("Domain cannot contain spaces.")
			continue
		}

		parts := strings.Split(input, ".")
		if len(parts) < 2 {
			errorColor.Println("Invalid domain format. Should be at least example.com")
			continue
		}

		return input
	}
}

// ReadConfirmation reads a confirmation (yes/no) from the user
func (r *Reader) ReadConfirmation(prompt string) bool {
	promptColor.Printf("%s (y/n): ", prompt)
	input := strings.ToLower(r.ReadLine())
	return input == "y" || input == "yes"
}

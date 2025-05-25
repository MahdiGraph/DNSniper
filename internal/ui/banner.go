package ui

import (
	"fmt"

	"github.com/fatih/color"
)

// Banner colors
var (
	titleColor    = color.New(color.FgHiCyan, color.Bold)
	subtitleColor = color.New(color.FgCyan)
)

// PrintBanner prints the DNSniper banner
func PrintBanner() {
	banner := `
_____  _   _  _____       _                 
|  __ \| \ | |/ ____|     (_)                
| |  | |  \| | (___  _ __  _ _ __   ___ _ __
| |  | | . ` + "`" + ` |\___ \| '_ \| | '_ \ / _ \ '__|
| |__| | |\  |____) | | | | | |_) |  __/ |   
|_____/|_| \_|_____/|_| |_|_| .__/ \___|_|   
                            | |              
                            |_|              
`
	titleColor.Println(banner)
	titleColor.Println("DNSniper v2.0 – Peace of Mind")
	subtitleColor.Println("Lock onto threats, restore your security")
	fmt.Println(string(color.New(color.FgHiCyan).Sprint("=================================================")))
}

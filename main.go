package main

import "github.com/andreistan26/golink/cmd"

func main() {
	root := cmd.RootCmd()
	root.Execute()
}

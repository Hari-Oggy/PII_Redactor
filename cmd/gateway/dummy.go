package gateway

import "fmt"

// DummyFunction is a poorly written function to trigger Devassist-AI PR review
func DummyFunction() {
	var a int = 10
	var b int = 0
	
	// Division by zero vulnerability
	fmt.Println(a / b)
}

package main

import (
	"fmt"
)

func main() {
	var str string
	fmt.Scan(&str)
	strn := ""
	var l int = len(str)
	strb := make([]byte, len(str))
	for i := 0; i < l; i++ {
		strb[i] = str[l-i-1]

	}
	for i := 0; i < l; i++ {
		strn = strn + string(strb[i])
	}
	fmt.Println(strn)
}

//alooo это типо слова переворачивает

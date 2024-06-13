/*
@Time : 2024/6/12 下午7:49
@Author : ljn
@File : utils
@Software: GoLand
*/

package utils

import "os"

// MustCheck panics when the error is not nil
func MustCheck(err error) {
	if err != nil {
		panic(err)
	}
}

// CloseFile attempts to close the passed file
// or panics with the actual error
func CloseFile(f *os.File) {
	err := f.Close()
	MustCheck(err)
}

// WriteToFile creates a file and writes content to it
func WriteToFile(filename, content string) {
	f, err := os.Create(filename)
	MustCheck(err)
	defer CloseFile(f)
	_, err = f.WriteString(content)
	MustCheck(err)
}

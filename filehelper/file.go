package filehelper

import (
	"fmt"
	"io/ioutil"
	"os"
)

// FileExists returns true if a file exists.
// This function does not check access errors.
func FileExists(fileName string) bool {
	_, err := os.Stat(fileName)
	return !os.IsNotExist(err)
}

// PathExists returns true if a path exists or cannot be accessed.
// Return the error if we cannot access because of a permission issue.
func PathExists(path string) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return true, err
	}
	return true, nil
}

// ReadFileByte reads the contents of a file and returns a []byte.
func ReadFileByte(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return ioutil.ReadAll(f)
}

// ReadFileString is the same as ReadFile but returns a string.
func ReadFileString(filename string) (string, error) {
	content, err := ReadFileByte(filename)
	return string(content), err
}

// WriteFile writes input to the file.
// File is overwritten if overwrite is set to true.
func WriteFile(input []byte, file string, overwrite bool) error {
	exists, err := PathExists(file)
	// Check access.
	if err != nil {
		return fmt.Errorf("filehelper.WriteFile: check access - %s", err.Error())
	}
	// Check if exists and if overwrite is set.
	if exists && !overwrite {
		return fmt.Errorf("filehelper.WriteFile: %s exists and overwrite is not set", file)
	}
	// Open/Create file.
	f, err := os.Create(file)
	if err != nil {
		return fmt.Errorf("filehelper.WriteFile: create file - %s", err.Error())
	}
	defer f.Close()
	// Write to file.
	n, err := f.Write(input)
	if err != nil {
		return fmt.Errorf("filehelper.WriteFile: write to file - %s", err.Error())
	}
	// Check if all input is written.
	if n != len(input) {
		return fmt.Errorf("filehelper.WriteFile: only %d bytes written out of %d", n, len(input))
	}
	return nil
}

// WriteFileString writes a string to a file.
// File is overwritten if overwrite is set to true.
func WriteFileString(input string, file string, overwrite bool) error {
	return WriteFile([]byte(input), file, overwrite)
}

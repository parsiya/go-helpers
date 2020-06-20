package filehelper

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
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
	// Check if all input was written.
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

// RemoveExtension removes the extension from a filename.
func RemoveExtension(filename string) string {
	ext := filepath.Ext(filename)
	return filename[:len(filename)-len(ext)]
}

// AddExtension removes the old extension and adds a new one.
func AddExtension(filename, ext string) string {
	filename = RemoveExtension(filename)
	// Return filename if extension is empty.
	if ext == "" {
		return filename
	}
	return filename + "." + ext
}

// ListFiles returns all files with a specific pattern under a path. The path
// is relative to root. Pattern is the typical "shell file name pattern"
// (e.g. *.exe or * to list all files).
func ListFiles(root, pattern string) (files []string, err error) {
	// Check if path exists.
	exists, err := PathExists(root)
	if err != nil {
		return files, err
	}
	if !exists {
		return files, fmt.Errorf("shared.ListFiles: path %s does not exist", root)
	}

	err = filepath.Walk(root, func(file string, info os.FileInfo, walkErr error) error {
		// Convert file path to /, otherwise match will not work (for some reason).
		file = filepath.ToSlash(file)
		match, matchErr := filepath.Match(pattern, file)
		if matchErr != nil {
			return fmt.Errorf("shared.ListFiles: match error %s", matchErr.Error())
		}
		if match && !info.IsDir() {
			relpath, relErr := filepath.Rel(root, file)
			if relErr != nil {
				// Theoretically this shouldn't happen because we are only parsing
				// files under root, every file path should be relative to root.
				// But if it does move on.
				// files = append(files, file)
				return nil
			}
			files = append(files, relpath)
		}
		return nil
	})
	return files, err
}

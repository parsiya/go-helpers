package pathhelper

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/mitchellh/go-homedir"
)

// HomeDir calls homedir.Dir() but changes the backslashes with forwardslashes
// on Windows.
func HomeDir() (string, error) {
	homedir, err := homedir.Dir()
	if err != nil {
		return "", fmt.Errorf("shared.HomeDir: %s", err.Error())
	}
	// ToSlash replaces \ with /. The opposite is filepath.FromSlash(string)
	return filepath.ToSlash(homedir), nil
}

// DesktopPath returns the path to Desktop on a Windows machine.
func DesktopPath() (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("shared.DesktopPath: not running Windows, running %s", runtime.GOOS)
	}
	home, err := HomeDir()
	return filepath.Join(home, "Desktop"), err
}

// DeletePath deletes a path and all its children from disk.
func DeletePath(pathname string) error {
	return os.RemoveAll(pathname)
}

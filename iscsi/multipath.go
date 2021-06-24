package iscsi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

type pathGroup struct {
	Paths []path `json:"paths"`
}

type path struct {
	Device string `json:"dev"`
}

// ExecWithTimeout execute a command with a timeout and returns an error if timeout is excedeed
func ExecWithTimeout(command string, args []string, timeout time.Duration) ([]byte, error) {
	debug.Printf("Executing command '%v' with args: '%v'.\n", command, args)

	// Create a new context and add a timeout to it
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Create command with context
	cmd := execCommandContext(ctx, command, args...)

	// This time we can simply use Output() to get the result.
	out, err := cmd.Output()
	debug.Println(err)

	// We want to check the context error to see if the timeout was executed.
	// The error returned by cmd.Output() will be OS specific based on what
	// happens when a process is killed.
	if ctx.Err() == context.DeadlineExceeded {
		debug.Printf("Command '%s' timeout reached.\n", command)
		return nil, ctx.Err()
	}

	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			debug.Printf("Non-zero exit code: %s\n", err)
			err = fmt.Errorf("%s", ee.Stderr)
		}
	}

	debug.Println("Finished executing command.")
	return out, err
}

// FlushMultipathDevice flushes a multipath device dm-x with command multipath -f /dev/dm-x
func FlushMultipathDevice(device *Device) error {
	devicePath := device.GetPath()
	debug.Printf("Flushing multipath device '%v'.\n", devicePath)

	timeout := 5 * time.Second
	_, err := execWithTimeout("multipath", []string{"-f", devicePath}, timeout)

	if err != nil {
		if _, e := osStat(devicePath); os.IsNotExist(e) {
			debug.Printf("Multipath device %v has been removed.\n", devicePath)
		} else {
			if strings.Contains(err.Error(), "map in use") {
				err = fmt.Errorf("device is probably still in use somewhere else: %v", err)
			}
			debug.Printf("Command 'multipath -f %v' did not succeed to delete the device: %v\n", devicePath, err)
			return err
		}
	}

	debug.Printf("Finshed flushing multipath device %v.\n", devicePath)
	return nil
}

// ResizeMultipathDevice resize a multipath device based on its underlying devices
func ResizeMultipathDevice(device *Device) error {
	debug.Printf("Resizing multipath device %s\n", device.GetPath())

	if output, err := execCommand("multipathd", "resize", "map", device.Name).CombinedOutput(); err != nil {
		return fmt.Errorf("could not resize multipath device: %s (%v)", output, err)
	}

	return nil
}

func addMultipathMap(devicePaths []string) error {
	var wwid string
	var path string

	for _, devicePath := range devicePaths {
		deviceWWID, err := getDeviceWWID(devicePath)
		if err != nil {
			return err
		}

		if wwid == "" {
			wwid = deviceWWID
			path = devicePath
		} else if deviceWWID != wwid {
			return errors.New(fmt.Sprintf("wwids doesn't match (%q != %q) for devices %q and %q", deviceWWID, wwid, devicePath, path))
		}
	}

	if output, err := execCommand("multipathd", "add", "map", wwid).CombinedOutput(); err != nil {
		return fmt.Errorf("could not add multipath map: %s (%v)", output, err)
	}

	for _, devicePath := range devicePaths {
		// maybe have to convert path to the form /dev/sdx or sdx first
		if output, err := execCommand("multipathd", "add", "path", devicePath).CombinedOutput(); err != nil {
			return fmt.Errorf("could not add multipath path: %s (%v)", output, err)
		}
	}

	return nil
}

func removeMultipathMap(wwid string, devices []Device) error {
	for _, device := range devices {
		// check with .Name et .GetPath()
		if output, err := execCommand("multipathd", "remove", "path", device.Name).CombinedOutput(); err != nil {
			return fmt.Errorf("could not remove multipath path: %s (%v)", output, err)
		}
	}

	if output, err := execCommand("multipathd", "remove", "map", wwid).CombinedOutput(); err != nil {
		return fmt.Errorf("could not remove multipath map: %s (%v)", output, err)
	}

	return nil
}

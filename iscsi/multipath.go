package iscsi

import (
	"context"
	"os"
	"os/exec"
	"time"
	"encoding/json"
)

type multipathDeviceMap struct {
	Map multipathMap `json:"map"`
}

type multipathMap struct {
	Name string `json:"name"`
	Uuid string `json:"uuid"`
	Sysfs string `json:"sysfs"`
	PathGroups []pathGroup `json:"path_groups"`
}

type pathGroup struct {
	Paths []path `json:"paths"`
}

type path struct {
	Device string `json:"dev"`
}

func ExecWithTimeout(command string, args []string, timeout time.Duration) ([]byte, error) {
	debug.Printf("Executing command '%v' with args: '%v'.\n", command, args)

	// Create a new context and add a timeout to it
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Create command with context
	cmd := exec.CommandContext(ctx, command, args...)

	// This time we can simply use Output() to get the result.
	out, err := cmd.Output()

	// We want to check the context error to see if the timeout was executed.
	// The error returned by cmd.Output() will be OS specific based on what
	// happens when a process is killed.
	if ctx.Err() == context.DeadlineExceeded {
		debug.Printf("Command '%s' timeout reached.\n", command)
		return nil, ctx.Err()
	}

	if err != nil {
		debug.Printf("Non-zero exit code: %s\n", err)
	}

	debug.Println("Finished executing command.")
	return out, err
}

func getMultipathMap(device string) (*multipathDeviceMap, error) {
	debug.Printf("Getting multipath map for device %s.\n", device)

	cmd := exec.Command("multipathd", "show", "map", device[1:], "json")
	out, err := cmd.Output()
	// debug.Printf(string(out))
	if err != nil {
		debug.Printf("An error occured while looking for multipath device map: %v\n", err)
		return nil, err
	}

	var deviceMap multipathDeviceMap;
	json.Unmarshal(out, &deviceMap) // TODO check error
	return &deviceMap, nil
}

func (deviceMap *multipathDeviceMap) GetSlaves() []string {
	var slaves []string

	for _, pathGroup := range deviceMap.Map.PathGroups {
		for _, path := range pathGroup.Paths {
			slaves = append(slaves, path.Device)
		}
	}

	return slaves
}

// FlushMultipathDevice flushes a multipath device dm-x with command multipath -f /dev/dm-x
func FlushMultipathDevice(device string) error {
	debug.Printf("Flushing multipath device '%v'.\n", device)

	timeout := 5 * time.Second
	_, err := execWithTimeout("multipath", []string{"-f", device}, timeout)

	if err != nil {
		if _, e := os.Stat(device); os.IsNotExist(e) {
			debug.Printf("Multipath device %v was deleted.\n", device)
		} else {
			debug.Printf("Command 'multipath -f %v' did not succeed to delete the device: %v\n", device, err)
			return err
		}
	}

	debug.Printf("Finshed flushing multipath device %v.\n", device)
	return nil
}

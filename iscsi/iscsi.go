package iscsi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const defaultPort = "3260"

var (
	debug           *log.Logger
	execCommand     = exec.Command
	execWithTimeout = ExecWithTimeout
)

type statFunc func(string) (os.FileInfo, error)
type globFunc func(string) ([]string, error)

type iscsiSession struct {
	Protocol string
	ID       int32
	Portal   string
	IQN      string
	Name     string
}

// TargetInfo contains connection information to connect to an ISCSI endpoint
type TargetInfo struct {
	Iqn    string `json:"iqn"`
	Portal string `json:"portal"`
	Port   string `json:"port"`
}

type deviceInfo struct {
	BlockDevices []Device
}

// Device contains informations about a device
type Device struct {
	Name      string   `json:"name"`
	Hctl      string   `json:"hctl"`
	Children  []Device `json:"children"`
	Type      string   `json:"type"`
	Vendor    string   `json:"vendor"`
	Model     string   `json:"model"`
	Revision  string   `json:"rev"`
	Transport string   `json:"tran"`
}

//Connector provides a struct to hold all of the needed parameters to make our iscsi connection
type Connector struct {
	VolumeName       string       `json:"volume_name"`
	Targets          []TargetInfo `json:"targets"`
	Lun              int32        `json:"lun"`
	AuthType         string       `json:"auth_type"`
	DiscoverySecrets Secrets      `json:"discovery_secrets"`
	SessionSecrets   Secrets      `json:"session_secrets"`
	Interface        string       `json:"interface"`

	MountTargetDevice *Device  `json:"mount_target_device"`
	Devices           []Device `json:"devices"`

	RetryCount      int32 `json:"retry_count"`
	CheckInterval   int32 `json:"check_interval"`
	DoDiscovery     bool  `json:"do_discovery"`
	DoCHAPDiscovery bool  `json:"do_chap_discovery"`
}

func init() {
	// by default we don't log anything, EnableDebugLogging() can turn on some tracing
	debug = log.New(ioutil.Discard, "", 0)
}

// EnableDebugLogging provides a mechanism to turn on debug logging for this package
// output is written to the provided io.Writer
func EnableDebugLogging(writer io.Writer) {
	debug = log.New(writer, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile)
}

// parseSession takes the raw stdout from the iscsiadm -m session command and encodes it into an iscsi session type
func parseSessions(lines string) []iscsiSession {
	entries := strings.Split(strings.TrimSpace(string(lines)), "\n")
	r := strings.NewReplacer("[", "",
		"]", "")

	var sessions []iscsiSession
	for _, entry := range entries {
		e := strings.Fields(entry)
		if len(e) < 4 {
			continue
		}
		protocol := strings.Split(e[0], ":")[0]
		id := r.Replace(e[1])
		id64, _ := strconv.ParseInt(id, 10, 32)
		portal := strings.Split(e[2], ",")[0]

		s := iscsiSession{
			Protocol: protocol,
			ID:       int32(id64),
			Portal:   portal,
			IQN:      e[3],
			Name:     strings.Split(e[3], ":")[1],
		}
		sessions = append(sessions, s)
	}
	return sessions
}

func sessionExists(tgtPortal, tgtIQN string) (bool, error) {
	sessions, err := getCurrentSessions()
	if err != nil {
		return false, err
	}
	for _, s := range sessions {
		if tgtIQN == s.IQN && tgtPortal == s.Portal {
			return true, nil
		}
	}
	return false, nil
}

func extractTransportName(output string) string {
	res := regexp.MustCompile(`iface.transport_name = (.*)\n`).FindStringSubmatch(output)
	if res == nil {
		return ""
	}
	if res[1] == "" {
		return "tcp"
	}
	return res[1]
}

func getCurrentSessions() ([]iscsiSession, error) {

	out, err := GetSessions()
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if ok && exitErr.ProcessState.Sys().(syscall.WaitStatus).ExitStatus() == 21 {
			return []iscsiSession{}, nil
		}
		return nil, err
	}
	sessions := parseSessions(out)
	return sessions, err
}

func waitForPathToExist(devicePath *string, maxRetries, intervalSeconds int, deviceTransport string) (bool, error) {
	return waitForPathToExistImpl(devicePath, maxRetries, intervalSeconds, deviceTransport, os.Stat, filepath.Glob)
}

func waitForPathToExistImpl(devicePath *string, maxRetries, intervalSeconds int, deviceTransport string, osStat statFunc, filepathGlob globFunc) (bool, error) {
	if devicePath == nil {
		return false, fmt.Errorf("Unable to check unspecified devicePath")
	}

	var err error
	for i := 0; i < maxRetries; i++ {
		err = nil
		if deviceTransport == "tcp" {
			_, err = osStat(*devicePath)
			if err != nil && !os.IsNotExist(err) {
				debug.Printf("Error attempting to stat device: %s", err.Error())
				return false, err
			} else if err != nil {
				debug.Printf("Device not found for: %s", *devicePath)
			}

		} else {
			fpath, _ := filepathGlob(*devicePath)
			if fpath == nil {
				err = os.ErrNotExist
			} else {
				// There might be a case that fpath contains multiple device paths if
				// multiple PCI devices connect to same iscsi target. We handle this
				// case at subsequent logic. Pick up only first path here.
				*devicePath = fpath[0]
			}
		}
		if err == nil {
			return true, nil
		}
		if i == maxRetries-1 {
			break
		}
		time.Sleep(time.Second * time.Duration(intervalSeconds))
	}
	return false, err
}

func getMultipathDevice(devices []Device) (*Device, error) {
	var deviceInfo deviceInfo
	var multipathDevice *Device
	var devicePaths []string

	for _, device := range devices {
		devicePaths = append(devicePaths, device.GetPath())
	}
	out, err := lsblk("-J", devicePaths)
	if err != nil {
		return nil, err
	}

	if err = json.Unmarshal(out, &deviceInfo); err != nil {
		return nil, err
	}

	for _, device := range deviceInfo.BlockDevices {
		if len(device.Children) != 1 {
			return nil, fmt.Errorf("Device is not mapped to exactly one multipath device: %v", device.Children)
		}
		if multipathDevice != nil && device.Children[0].Name != multipathDevice.Name {
			return nil, fmt.Errorf("Devices don't share a common multipath device: %v", devices)
		}
		multipathDevice = &device.Children[0]
	}

	if multipathDevice.Type != "mpath" {
		return nil, fmt.Errorf("Device is not of mpath type: %v", multipathDevice)
	}

	return multipathDevice, nil
}

// Connect attempts to connect a volume to this node using the provided Connector info
func (c *Connector) Connect() (string, error) {
	var lastErr error
	if c.RetryCount == 0 {
		c.RetryCount = 10
	}
	if c.CheckInterval == 0 {
		c.CheckInterval = 1
	}

	if c.RetryCount < 0 || c.CheckInterval < 0 {
		return "", fmt.Errorf("Invalid RetryCount and CheckInterval combination, both must be positive integers. "+
			"RetryCount: %d, CheckInterval: %d", c.RetryCount, c.CheckInterval)
	}

	iFace := "default"
	if c.Interface != "" {
		iFace = c.Interface
	}

	// make sure our iface exists and extract the transport type
	out, err := ShowInterface(iFace)
	if err != nil {
		return "", err
	}
	iscsiTransport := extractTransportName(out)

	var devicePaths []string
	for _, target := range c.Targets {
		debug.Printf("process targetIqn: %s, portal: %s\n", target.Iqn, target.Portal)
		baseArgs := []string{"-m", "node", "-T", target.Iqn, "-p", target.Portal}
		// Rescan sessions to discover newly mapped LUNs. Do not specify the interface when rescanning
		// to avoid establishing additional sessions to the same target.
		if _, err := iscsiCmd(append(baseArgs, []string{"-R"}...)...); err != nil {
			debug.Printf("failed to rescan session, err: %v", err)
		}

		// create our devicePath that we'll be looking for based on the transport being used
		port := defaultPort
		if target.Port != "" {
			port = target.Port
		}
		// portal with port
		p := strings.Join([]string{target.Portal, port}, ":")
		devicePath := strings.Join([]string{"/dev/disk/by-path/ip", p, "iscsi", target.Iqn, "lun", fmt.Sprint(c.Lun)}, "-")
		if iscsiTransport != "tcp" {
			devicePath = strings.Join([]string{"/dev/disk/by-path/pci", "*", "ip", p, "iscsi", target.Iqn, "lun", fmt.Sprint(c.Lun)}, "-")
		}

		exists, _ := sessionExists(p, target.Iqn)
		if exists {
			if exists, err := waitForPathToExist(&devicePath, 1, 1, iscsiTransport); exists {
				debug.Printf("Appending device path: %s", devicePath)
				devicePaths = append(devicePaths, devicePath)
				continue
			} else if err != nil {
				return "", err
			}
		}

		if c.DoDiscovery {
			// build discoverydb and discover iscsi target
			if err := Discoverydb(p, iFace, c.DiscoverySecrets, c.DoCHAPDiscovery); err != nil {
				debug.Printf("Error in discovery of the target: %s\n", err.Error())
				lastErr = err
				continue
			}
		}

		if c.DoCHAPDiscovery {
			// Make sure we don't log the secrets
			err := CreateDBEntry(target.Iqn, p, iFace, c.DiscoverySecrets, c.SessionSecrets)
			if err != nil {
				debug.Printf("Error creating db entry: %s\n", err.Error())
				continue
			}
		}

		// perform the login
		err = Login(target.Iqn, p)
		if err != nil {
			debug.Printf("failed to login, err: %v", err)
			lastErr = err
			continue
		}
		retries := int(c.RetryCount / c.CheckInterval)
		if exists, err := waitForPathToExist(&devicePath, retries, int(c.CheckInterval), iscsiTransport); exists {
			devicePaths = append(devicePaths, devicePath)
			continue
		} else if err != nil {
			lastErr = fmt.Errorf("Couldn't attach disk, err: %v", err)
		}
	}

	// GetIscsiDevices returns all devices if no paths are given
	if len(devicePaths) < 1 {
		c.Devices = []Device{}
	} else {
		c.Devices, err = GetIscsiDevices(devicePaths)
		if err != nil {
			return "", err
		}
	}

	if len(c.Devices) < 1 {
		iscsiCmd([]string{"-m", "iface", "-I", iFace, "-o", "delete"}...)
		return "", fmt.Errorf("failed to find device path: %s, last error seen: %v", devicePaths, lastErr)
	}

	mountTargetDevice, err := c.getMountTargetDevice()
	c.MountTargetDevice = mountTargetDevice
	if err != nil {
		debug.Printf("Connect failed: %v", err)
		RemoveScsiDevices(c.Devices...)
		c.MountTargetDevice = nil
		c.Devices = []Device{}
		return "", err
	}

	return c.MountTargetDevice.GetPath(), nil
}

//Disconnect performs a disconnect operation on a volume
func Disconnect(tgtIqn string, portals []string) error {
	err := Logout(tgtIqn, portals)
	if err != nil {
		return err
	}
	err = DeleteDBEntry(tgtIqn)
	return err
}

// DisconnectVolume removes a volume from a Linux host.
func (c *Connector) DisconnectVolume() error {
	// Steps to safely remove an iSCSI storage volume from a Linux host are as following:
	// 1. Unmount the disk from a filesystem on the system.
	// 2. Flush the multipath map for the disk we’re removing (if multipath is enabled).
	// 3. Remove the physical disk entities that Linux maintains.
	// 4. Take the storage volume (disk) offline on the storage subsystem.
	// 5. Rescan the iSCSI sessions (after unmapping only).
	//
	// DisconnectVolume focuses on step 2 and 3.
	// Note: make sure the volume is already unmounted before calling this method.

	if c.IsMultipathEnabled() {
		debug.Printf("Removing multipath device in path %s.\n", c.MountTargetDevice.GetPath())
		err := FlushMultipathDevice(c.MountTargetDevice)
		if err != nil {
			return err
		}

		if err := RemoveScsiDevices(c.Devices...); err != nil {
			return err
		}
	} else {
		devicePath := c.MountTargetDevice.GetPath()
		debug.Printf("Removing normal device in path %s.\n", devicePath)
		device, err := GetIscsiDevice(devicePath)
		if err != nil {
			return err
		}
		if err = RemoveScsiDevices(*device); err != nil {
			return err
		}
	}

	debug.Printf("Finished disconnecting volume.\n")
	return nil
}

func (c *Connector) getMountTargetDevice() (*Device, error) {
	if c.IsMultipathEnabled() {
		multipathDevice, err := getMultipathDevice(c.Devices)
		if err != nil {
			debug.Printf("mount target is not a multipath device: %v", err)
			return nil, err
		}
		debug.Printf("mount target is a multipath device")
		return multipathDevice, nil
	}

	if len(c.Devices) == 0 {
		return nil, fmt.Errorf("could not find mount target device: connector does not contain any device")
	}

	return &c.Devices[0], nil
}

// IsMultipathEnabled check if multipath is enabled on devices handled by this connector
func (c *Connector) IsMultipathEnabled() bool {
	return len(c.Devices) > 1
}

// GetIscsiDevice get an SCSI device from a device name
func GetIscsiDevice(deviceName string) (*Device, error) {
	iscsiDevices, err := GetIscsiDevices([]string{deviceName})
	if err != nil {
		return nil, err
	}
	if len(iscsiDevices) == 0 {
		return nil, fmt.Errorf("device %q not found", deviceName)
	}
	return &iscsiDevices[0], nil
}

// GetScsiDevices get SCSI devices from device paths
// It will returns all SCSI devices if no paths are given
func GetScsiDevices(devicePaths []string) ([]Device, error) {
	debug.Printf("Getting info about SCSI devices %s.\n", devicePaths)

	out, err := lsblk("-JS", devicePaths)
	if err != nil {
		debug.Printf("An error occured while looking info about SCSI devices: %v", err)
		return nil, err
	}

	var deviceInfo deviceInfo
	err = json.Unmarshal(out, &deviceInfo)
	if err != nil {
		return nil, err
	}

	return deviceInfo.BlockDevices, nil
}

// GetIscsiDevices get iSCSI devices from device paths
// It will returns all iSCSI devices if no paths are given
func GetIscsiDevices(devicePaths []string) (devices []Device, err error) {
	scsiDevices, err := GetScsiDevices(devicePaths)
	if err != nil {
		return
	}

	for i := range scsiDevices {
		device := &scsiDevices[i]
		if device.Transport == "iscsi" {
			devices = append(devices, *device)
		}
	}

	return
}

func lsblk(flags string, devicePaths []string) ([]byte, error) {
	out, err := exec.Command("lsblk", append([]string{flags}, devicePaths...)...).CombinedOutput()
	debug.Printf("lsblk %s %s", flags, strings.Join(devicePaths, " "))
	if err != nil {
		return nil, fmt.Errorf("lsblk: %s", string(out))
	}

	return out, nil
}

func writeInScsiDeviceFile(hctl string, file string, content string) error {
	filename := filepath.Join("/sys/class/scsi_device", hctl, "device", file)
	debug.Printf("Write %q in %q.\n", content, filename)

	f, err := os.OpenFile(filename, os.O_TRUNC|os.O_WRONLY, 0200)
	if err != nil {
		debug.Printf("Error while opening file %v: %v\n", filename, err)
		return err
	}

	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		debug.Printf("Error while writing to file %v: %v", filename, err)
		return err
	}

	return nil
}

// RemoveScsiDevices removes scsi device(s) from a Linux host.
func RemoveScsiDevices(devices ...Device) error {
	debug.Printf("Removing scsi devices %v.\n", devices)

	var errs []error
	for _, device := range devices {
		debug.Printf("Flush scsi device %v.\n", device.Name)
		out, err := exec.Command("blockdev", "--flushbufs", device.GetPath()).CombinedOutput()
		if err != nil {
			debug.Printf("Command 'blockdev --flushbufs %v' did not succeed to flush the device: %v\n", device.Name, err)
			return errors.New(string(out))
		}

		debug.Printf("Put scsi device %v offline.\n", device.Name)
		err = device.Shutdown()
		if err != nil {
			if !os.IsNotExist(err) { // Ignore device already removed
				errs = append(errs, err)
			}
			continue
		}

		debug.Printf("Delete scsi device %v.\n", device.Name)
		err = device.Delete()
		if err != nil {
			if !os.IsNotExist(err) { // Ignore device already removed
				errs = append(errs, err)
			}
			continue
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}
	debug.Println("Finshed removing SCSI devices.")
	return nil
}

// Persist persists the Connector to the specified file (ie /var/lib/pfile/myConnector.json)
func (c *Connector) Persist(filePath string) error {
	//file := path.Join("mnt", c.VolumeName+".json")
	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("error creating iscsi persistence file %s: %s", filePath, err)
	}
	defer f.Close()
	encoder := json.NewEncoder(f)
	if err = encoder.Encode(c); err != nil {
		return fmt.Errorf("error encoding connector: %v", err)
	}
	return nil
}

// GetConnectorFromFile attempts to create a Connector using the specified json file (ie /var/lib/pfile/myConnector.json)
func GetConnectorFromFile(filePath string) (*Connector, error) {
	f, err := ioutil.ReadFile(filePath)
	if err != nil {
		return &Connector{}, err

	}
	data := Connector{}
	err = json.Unmarshal([]byte(f), &data)
	if err != nil {
		return &Connector{}, err
	}

	return &data, nil
}

// GetPath returns the path of a device
func (d *Device) GetPath() string {
	if d.Type == "mpath" {
		return filepath.Join("/dev/mapper", d.Name)
	}

	return filepath.Join("/dev", d.Name)
}

// WriteDeviceFile write in a device file
func (d *Device) WriteDeviceFile(name string, content string) error {
	return writeInScsiDeviceFile(d.Hctl, name, content)
}

// Shutdown turn off an scsi device by writing offline\n in /sys/class/scsi_device/h:c:t:l/device/state
func (d *Device) Shutdown() error {
	return writeInScsiDeviceFile(d.Hctl, "state", "offline\n")
}

// Delete detach an scsi device by writing 1 in /sys/class/scsi_device/h:c:t:l/device/delete
func (d *Device) Delete() error {
	return writeInScsiDeviceFile(d.Hctl, "delete", "1")
}

// Rescan rescan an scsi device by writing 1 in /sys/class/scsi_device/h:c:t:l/device/rescan
func (d *Device) Rescan() error {
	return writeInScsiDeviceFile(d.Hctl, "rescan", "1")
}

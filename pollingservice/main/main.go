package main

import (
	"fmt"
	"reflect"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/ContinuumLLC/platform-api-model/clients/model/Golang/resourceModel/asset"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	serviceConfigFailureActionsFlag   = 4
	serviceConfigDelayedAutoStartInfo = 3
	serviceStatusAutoDelayedStart     = "Automatic (Delayed Start)"
	serviceDelete                     = "DELETE"
	thresholdDefaultTime              = 30
	thresholdDefaultTimeInMultiples   = 2
	evtTypeAssetService               = "assetService"
	default10Seconds                  = 10
)

var (
	modadvapi32              = syscall.NewLazyDLL("advapi32.dll")
	procQueryServiceConfig2W = modadvapi32.NewProc("QueryServiceConfig2W")
)

//Config service config
type Config struct {
	ServiceType      uint32
	StartType        uint32
	ErrorControl     uint32
	BinaryPathName   string // fully qualified path to the service binary file, can also include arguments for an auto-start service
	ServiceStartName string // name of the account under which the service should run
	DisplayName      string
}

var serviceStartTypeMap = map[int]string{
	0: "BootStart",
	1: "SystemStart",
	2: "Automatic",
	3: "Manual",
	4: "Disabled",
}

var serviceStatusMap = map[uint]string{
	1:          "Stopped",
	2:          "StartPending",
	3:          "StopPending",
	4:          "Running",
	5:          "ContinuePending",
	6:          "PausePending",
	7:          "Paused",
	0xffffffff: "NoChange",
}

type serviceMap struct {
	lastServiceData asset.Service
	currServiceData asset.Service
	firstTimeReport time.Time
	currTimeReport  time.Time
}

func main() {
	fmt.Println("Start")
	ListenSVCEvents()
}

//ListenSVCEvents listens service events
func ListenSVCEvents() { // nolint
	bufferSize := uint32(1024)
	buffer := make([]byte, bufferSize)
	latest, _ := createServiceSnapShot(buffer, &bufferSize)

	for {

		time.Sleep(3 * time.Second)
		currentSnapShot, err := createServiceSnapShot(buffer, &bufferSize)
		if err != nil {
			fmt.Println("Unable to take current service snapshot %v", err)
			continue
		}

		assetServiceArr := diffServiceSnapShot(latest, currentSnapShot)
		fmt.Println(assetServiceArr)
		if 0 != len(assetServiceArr) {
			fmt.Println("Asset service changed data for%+v", assetServiceArr)
		}
	}

}

func diffServiceSnapShot(last map[string]asset.Service, current map[string]asset.Service) (assetServiceArr []asset.Service) {

	for _, svcObj := range current {
		if val, ok := last[svcObj.Name]; ok {
			if !reflect.DeepEqual(val, svcObj) {
				assetServiceArr = append(assetServiceArr, svcObj)
				last[val.Name] = svcObj
			}

		} else {
			assetServiceArr = append(assetServiceArr, svcObj)
			last[svcObj.Name] = svcObj
		}
	}

	//Now we need to check the service which might be deleted.
	for _, svcObj := range last {
		if _, ok := current[svcObj.Name]; !ok {
			svcObj.ServiceStatus = serviceDelete
			assetServiceArr = append(assetServiceArr, svcObj)
		}
	}

	//Now update the last map, with the delete service
	for _, svc := range assetServiceArr {
		if svc.ServiceStatus == serviceDelete {
			delete(last, svc.Name)
		}
	}

	return
}

func createServiceSnapShot(buffer []byte, buffSize *uint32) (map[string]asset.Service, error) {
	//var servicelist []asset.Service
	var serviceAttributes asset.Service
	assetServiceMap := make(map[string]asset.Service)
	var err error

	svcMgr, err := mgr.Connect()
	if nil != err {
		return assetServiceMap, err
	}
	defer svcMgr.Disconnect()

	svcList, _ := svcMgr.ListServices()

	for _, name := range svcList {
		serviceHandle, err := OpenServiceForQueryConfig(svcMgr.Handle, name)

		if nil == err {
			cfg, err := QueryServiceConfig(serviceHandle, buffer, buffSize)
			if nil == err {
				serviceAttributes.Name = name
				serviceAttributes.DisplayName = cfg.DisplayName
				serviceAttributes.ExecutablePath = cfg.BinaryPathName
				serviceAttributes.LogOnAs = cfg.ServiceStartName

				st := int(cfg.StartType)
				serviceAttributes.StartupType = serviceStartTypeMap[st]

				ser, _ := QueryServiceStatus(serviceHandle)
				ss := uint(ser.CurrentState)
				serviceAttributes.ServiceStatus = serviceStatusMap[ss]

				serviceAttributes.Win32ExitCode = ser.Win32ExitCode
				serviceAttributes.ServiceSpecificExitCode = ser.ServiceSpecificExitCode

				stopEnableActionCheck, _ := QueryServiceConfigFlag(serviceHandle, serviceConfigFailureActionsFlag)
				if stopEnableActionCheck {
					serviceAttributes.StopEnableAction = true
				} else {
					serviceAttributes.StopEnableAction = false
				}

				delayedAutoStartCheck, _ := QueryServiceConfigFlag(serviceHandle, serviceConfigDelayedAutoStartInfo)
				if delayedAutoStartCheck {
					serviceAttributes.DelayedAutoStart = true
				} else {
					serviceAttributes.DelayedAutoStart = false
				}

				if (serviceAttributes.DelayedAutoStart) && (serviceAttributes.StartupType == "Automatic") {
					serviceAttributes.StartupType = serviceStatusAutoDelayedStart
				}

				assetServiceMap[serviceAttributes.Name] = serviceAttributes
				//servicelist = append(servicelist, serviceAttributes)
			}
			_ = CloseService(serviceHandle)
		}
	}
	return assetServiceMap, nil
}

//CloseService closes the service handle
func CloseService(h windows.Handle) error {
	return windows.CloseServiceHandle(h)
}

//OpenServiceForQueryConfig query config
func OpenServiceForQueryConfig(handle windows.Handle, name string) (h windows.Handle, err error) {
	h, err = windows.OpenService(handle, syscall.StringToUTF16Ptr(name), windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
	return
}

//QueryServiceStatus returns current status of service s.
func QueryServiceStatus(service windows.Handle) (windows.SERVICE_STATUS, error) {
	var t windows.SERVICE_STATUS
	err := windows.QueryServiceStatus(service, &t)
	if err != nil {
		return windows.SERVICE_STATUS{}, err
	}
	return t, nil
}

//QueryServiceConfigFlag query service flags
func QueryServiceConfigFlag(service windows.Handle, infoLevel uint32) (serviceConfigFlag bool, err error) {

	var serviceConfigData int32
	var buffSize = uint32(unsafe.Sizeof(serviceConfigData))
	var bytesNeeded uint32
	r1, _, e1 := syscall.Syscall6(procQueryServiceConfig2W.Addr(), 5, uintptr(service), uintptr(infoLevel), uintptr(unsafe.Pointer(&serviceConfigData)), uintptr(buffSize), uintptr(unsafe.Pointer(&bytesNeeded)), 0)
	if r1 == 0 {
		if e1 != 0 {
			err = e1
		} else {
			err = syscall.EINVAL
		}
	}

	if 1 == serviceConfigData {
		serviceConfigFlag = true
	} else {
		serviceConfigFlag = false
	}
	return
}

//QueryServiceConfig to query status
func QueryServiceConfig(handle windows.Handle, buffer []byte, buffSize *uint32) (Config, error) {
	var p *windows.QUERY_SERVICE_CONFIG
	n := *buffSize
	for {
		p = (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buffer[0]))
		err := windows.QueryServiceConfig(handle, p, *buffSize, &n)
		if err == nil {
			break
		}
		if err.(syscall.Errno) != syscall.ERROR_INSUFFICIENT_BUFFER {
			return Config{}, err
		}
		if *buffSize <= uint32(len(buffer)) {
			return Config{}, err
		}
		*buffSize = n
		buffer = make([]byte, *buffSize)
	}
	return Config{
		ServiceType:      p.ServiceType,
		StartType:        p.StartType,
		ErrorControl:     p.ErrorControl,
		BinaryPathName:   UTF16PtrToString(p.BinaryPathName),
		ServiceStartName: UTF16PtrToString(p.ServiceStartName),
		DisplayName:      UTF16PtrToString(p.DisplayName),
	}, nil

}

//UTF16PtrToString converts utf16 pointer string to string
func UTF16PtrToString(p *uint16) string {
	return lpOleStrToString(p)
}

func lpOleStrToString(cs *uint16) string {
	if cs == nil {
		return ""
	}

	length := lpOleStrLen(cs)
	if 0 == length {
		return ""
	}

	us := make([]uint16, 0, (length + 1))
	for p := uintptr(unsafe.Pointer(cs)); ; p += 2 {
		u := *(*uint16)(unsafe.Pointer(p))
		if u == 0 {
			return string(utf16.Decode(us[0:length]))
		}
		us = append(us, u)
	}
}

func lpOleStrLen(cs *uint16) (length int64) {
	if nil == cs {
		return 0
	}
	length = 0
	for p := uintptr(unsafe.Pointer(cs)); ; p += 2 {
		u := *(*uint16)(unsafe.Pointer(p))
		if u == 0 {
			return
		}
		length++
	}
	return
}

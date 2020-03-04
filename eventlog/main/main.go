package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"time"
	"unsafe"

	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/winlogbeat/sys"
	"github.com/elastic/beats/winlogbeat/sys/eventlogging"
	win "github.com/elastic/beats/winlogbeat/sys/wineventlog"
	"golang.org/x/sys/windows"
)

const (
	// MaxInsertStrings is the maximum number of strings that can be formatted by
	// FormatMessage API.
	MaxInsertStrings        = 99
	eventIDLowerMask uint32 = 0xFFFF
	eventIDUpperMask uint32 = 0xFFFF0000
)

var (
	nullPlaceholder    = []byte{'(', 0, 'n', 0, 'u', 0, 'l', 0, 'l', 0, ')', 0, 0, 0}
	nullPlaceholderPtr = uintptr(unsafe.Pointer(&nullPlaceholder[0]))
)

// winEventLogRecord is equivalent to EVENTLOGRECORD.
// See https://msdn.microsoft.com/en-us/library/windows/desktop/aa363646(v=vs.85).aspx
type eventLogRecord struct {
	length        uint32 // The size of this event record, in bytes
	reserved      uint32 // value that is always set to ELF_LOG_SIGNATURE (the value is 0x654c664c), which is ASCII for eLfL
	recordNumber  uint32 // The number of the record.
	timeGenerated uint32 // time at which this entry was submitted
	timeWritten   uint32 // time at which this entry was received by the service to be written to the log
	eventID       uint32 // The event identifier. The value is specific to the event source for the event, and is used
	// with source name to locate a description string in the message file for the event source.
	eventType           uint16 // The type of event
	numStrings          uint16 // number of strings present in the log
	eventCategory       uint16 // category for this event
	reservedFlags       uint16 // Reserved
	closingRecordNumber uint32 // Reserved
	stringOffset        uint32 // offset of the description strings within this event log record
	userSidLength       uint32 // size of the UserSid member, in bytes. This value can be zero if no security identifier was provided
	userSidOffset       uint32 // offset of the security identifier (SID) within this event log record
	dataLength          uint32 // size of the event-specific data in bytes
	dataOffset          uint32 // offset of the event-specific information within this event log record, in bytes

	//
	// Then follows the extra data.
	//
	// TCHAR SourceName[]
	// TCHAR Computername[]
	// SID   UserSid
	// TCHAR Strings[]
	// BYTE  Data[]
	// CHAR  Pad[]
	// DWORD Length;

	sourceName   string
	computerName string
	userSid      []byte
}

func main() {
	isWinAPIAvaliable, _ := win.IsAvailable()

	fmt.Println(isWinAPIAvaliable)

	hFile, err := eventlogging.OpenEventLog("", `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Application`)
	if err != nil {
		fmt.Println("failed to open eventlog with error %v", err)
	}

	lpBuffer := make([]byte, 102400)
	var level uint32 = 0

	flags := eventlogging.EVENTLOG_SEQUENTIAL_READ | eventlogging.EVENTLOG_FORWARDS_READ

	res, err := eventlogging.ReadEventLog(hFile, flags, level, lpBuffer)
	fmt.Println(string(res), err)

	lBuffer := make([]byte, 102400)
	rec, _, err := RenderEvents(lpBuffer, 0, lBuffer, &StringInserts{})
	fmt.Println(len(rec))

	for _, e := range rec {
		fmt.Printf("%+v \n", e)
	}
}

// unixTime takes a time which is an unsigned 32-bit integer, and converts it
// into a Golang time.Time pointer formatted as a unix time.
func unixTime(sec uint32) time.Time {
	t := time.Unix(int64(sec), 0)
	return t
}

// RenderEvents reads raw events from the provided buffer, formats them into
// structured events, and adds each on to a slice that is returned.
func RenderEvents(
	eventsRaw []byte,
	lang uint32,
	buffer []byte,
	insertStrings *StringInserts,
) ([]sys.Event, int, error) {
	var events []sys.Event
	var offset int
	for {
		if offset >= len(eventsRaw) {
			break
		}

		// Read a single EVENTLOGRECORD from the buffer.
		record, err := parseEventLogRecord(eventsRaw[offset:])
		if err != nil {
			return nil, 0, err
		}

		var qualifier = uint16((record.eventID & eventIDUpperMask) >> 16)
		var eventID = record.eventID & eventIDLowerMask
		event := sys.Event{
			Provider:        sys.Provider{Name: record.sourceName},
			EventIdentifier: sys.EventIdentifier{ID: eventID, Qualifiers: qualifier},
			LevelRaw:        uint8(record.eventType), // Possible overflow
			TaskRaw:         record.eventCategory,
			TimeCreated:     sys.TimeCreated{unixTime(record.timeGenerated)},
			RecordID:        uint64(record.recordNumber),
			Computer:        record.computerName,
			Level:           string(record.eventType),
		}

		// Create a slice from the larger buffer only data from the one record.
		// The upper bound has been validated already by parseEventLogRecord.
		recordBuf := eventsRaw[offset : offset+int(record.length)]
		offset += int(record.length)

		// Parse and format the user that logged the event.
		sid, _ := parseSID(record, recordBuf) // TODO: do something with this error
		if sid != nil {
			event.User = *sid
		}

		if record.numStrings > MaxInsertStrings {
			logp.Warn("Record contains %d strings, more than the limit %d. Excess will be ignored.",
				record.numStrings, MaxInsertStrings)
			record.numStrings = MaxInsertStrings
		}
		// Parse the UTF-16 message insert strings.
		if err = insertStrings.Parse(record, recordBuf); err != nil {
			event.RenderErr = append(event.RenderErr, err.Error())
			events = append(events, event)
			continue
		}

		for _, s := range insertStrings.Strings() {
			event.EventData.Pairs = append(event.EventData.Pairs, sys.KeyValue{Value: s})
		}

		fmt.Printf("event:  %+v \n \n", event)
	}

	return events, 0, nil
}

func parseSID(record eventLogRecord, buffer []byte) (*sys.SID, error) {
	if record.userSidLength == 0 {
		return nil, nil
	}

	sid := (*windows.SID)(unsafe.Pointer(&buffer[record.userSidOffset]))
	identifier := sid.String()

	return &sys.SID{Identifier: identifier}, nil
}

// parseEventLogRecord parses a single Windows EVENTLOGRECORD struct from the
// buffer.
func parseEventLogRecord(buffer []byte) (eventLogRecord, error) {
	var record eventLogRecord
	reader := bytes.NewReader(buffer)

	// Length
	err := binary.Read(reader, binary.LittleEndian, &record.length)
	if err != nil {
		return record, err
	}
	if len(buffer) < int(record.length) {
		return record, fmt.Errorf("Decoded EVENTLOGRECORD length (%d) is "+
			"greater than the buffer length (%d)", record.length, len(buffer))
	}

	// Reserved
	err = binary.Read(reader, binary.LittleEndian, &record.reserved)
	if err != nil {
		return record, err
	}
	if record.reserved != uint32(0x654c664c) {
		return record, fmt.Errorf("Buffer does not contain ELF_LOG_SIGNATURE. "+
			"The data is invalid. Value is %X", record.reserved)
	}

	// Buffer appears to be value so slice it to the adjust length.
	buffer = buffer[:record.length]
	reader = bytes.NewReader(buffer)
	reader.Seek(8, 0)

	// RecordNumber
	err = binary.Read(reader, binary.LittleEndian, &record.recordNumber)
	if err != nil {
		return record, err
	}

	// TimeGenerated
	err = binary.Read(reader, binary.LittleEndian, &record.timeGenerated)
	if err != nil {
		return record, err
	}

	// TimeWritten
	err = binary.Read(reader, binary.LittleEndian, &record.timeWritten)
	if err != nil {
		return record, err
	}

	// EventID
	err = binary.Read(reader, binary.LittleEndian, &record.eventID)
	if err != nil {
		return record, err
	}

	// EventType
	err = binary.Read(reader, binary.LittleEndian, &record.eventType)
	if err != nil {
		return record, err
	}

	// NumStrings
	err = binary.Read(reader, binary.LittleEndian, &record.numStrings)
	if err != nil {
		return record, err
	}

	// EventCategory
	err = binary.Read(reader, binary.LittleEndian, &record.eventCategory)
	if err != nil {
		return record, err
	}

	// ReservedFlags (2 bytes), ClosingRecordNumber (4 bytes)
	_, err = reader.Seek(6, 1)
	if err != nil {
		return record, err
	}

	// StringOffset
	err = binary.Read(reader, binary.LittleEndian, &record.stringOffset)
	if err != nil {
		return record, err
	}
	if record.numStrings > 0 && record.stringOffset > record.length {
		return record, fmt.Errorf("StringOffset value (%d) is invalid "+
			"because it is greater than the Length (%d)", record.stringOffset,
			record.length)
	}

	// UserSidLength
	err = binary.Read(reader, binary.LittleEndian, &record.userSidLength)
	if err != nil {
		return record, err
	}

	// UserSidOffset
	err = binary.Read(reader, binary.LittleEndian, &record.userSidOffset)
	if err != nil {
		return record, err
	}
	if record.userSidLength > 0 && record.userSidOffset > record.length {
		return record, fmt.Errorf("UserSidOffset value (%d) is invalid "+
			"because it is greater than the Length (%d)", record.userSidOffset,
			record.length)
	}

	// DataLength
	err = binary.Read(reader, binary.LittleEndian, &record.dataLength)
	if err != nil {
		return record, err
	}

	// DataOffset
	err = binary.Read(reader, binary.LittleEndian, &record.dataOffset)
	if err != nil {
		return record, err
	}

	// SourceName (null-terminated UTF-16 string)
	begin, _ := reader.Seek(0, 1)
	sourceName, length, err := sys.UTF16BytesToString(buffer[begin:])
	if err != nil {
		return record, err
	}
	record.sourceName = sourceName
	begin, err = reader.Seek(int64(length), 1)
	if err != nil {
		return record, err
	}

	// ComputerName (null-terminated UTF-16 string)
	computerName, length, err := sys.UTF16BytesToString(buffer[begin:])
	if err != nil {
		return record, err
	}
	record.computerName = computerName
	_, err = reader.Seek(int64(length), 1)
	if err != nil {
		return record, err
	}

	return record, nil
}

// StringInserts stores the string inserts for an event, as arrays of string
// and pointer to UTF-16 zero-terminated string suitable to be passed to
// the Windows API. The array of pointers has enough entries to ensure that
// a call to FormatMessage will never crash.
type StringInserts struct {
	pointers [MaxInsertStrings]uintptr
	inserts  []string
	address  uintptr
}

// Parse parses the insert strings from buffer which should contain
// an eventLogRecord.
func (b *StringInserts) Parse(record eventLogRecord, buffer []byte) error {
	if b.inserts == nil { // initialise struct
		b.inserts = make([]string, 0, MaxInsertStrings)
		b.address = reflect.ValueOf(&b.pointers[0]).Pointer()
	}
	b.clear()

	n := int(record.numStrings)
	if n > MaxInsertStrings {
		return fmt.Errorf("number of insert strings in the record (%d) is larger than the limit (%d)", n, MaxInsertStrings)
	}

	b.inserts = b.inserts[:n]
	if n == 0 {
		return nil
	}
	offset := int(record.stringOffset)
	bufferPtr := reflect.ValueOf(&buffer[0]).Pointer()

	for i := 0; i < n; i++ {
		if offset > len(buffer) {
			return fmt.Errorf("Failed reading string number %d, "+
				"offset=%d, len(buffer)=%d, record=%+v", i+1, offset,
				len(buffer), record)
		}
		insertStr, length, err := sys.UTF16BytesToString(buffer[offset:])
		if err != nil {
			return err
		}
		b.inserts[i] = insertStr
		b.pointers[i] = bufferPtr + uintptr(offset)
		offset += length
	}

	return nil
}

// Strings returns the array of strings representing the insert strings.
func (b *StringInserts) Strings() []string {
	return b.inserts
}

// Pointer returns a pointer to an array of UTF-16 strings suitable to be
// passed to the FormatMessage API.
func (b *StringInserts) Pointer() uintptr {
	return b.address
}

func (b *StringInserts) clear() {
	for i := 0; i < MaxInsertStrings && b.pointers[i] != nullPlaceholderPtr; i++ {
		b.pointers[i] = nullPlaceholderPtr
	}
}

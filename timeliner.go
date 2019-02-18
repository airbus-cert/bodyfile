package body

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"time"
)

type Entry struct {
	// MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
	MD5              string
	Name             string
	Inode            int
	Mode             string
	UID              int
	GID              int
	Size             int
	AccessTime       time.Time
	ModificationTime time.Time
	ChangeTime       time.Time
	CreationTime     time.Time
}

func (e *Entry) TimeFilter(filter DateFilter) bool {
	ret := false
	ret = ret || filterDateTime(filter, e.AccessTime)
	ret = ret || filterDateTime(filter, e.ModificationTime)
	ret = ret || filterDateTime(filter, e.CreationTime)
	ret = ret || filterDateTime(filter, e.ChangeTime)
	return ret
}

func filterDateTime(filter DateFilter, t time.Time) bool {
	ret := false
	if filter.Date != nil {
		ret = ret || filterDate(*filter.Date, t)
	}

	if filter.Time != nil {
		ret = ret || filterTime(*filter.Time, t)
	}

	if filter.Weekday != nil {
		ret = ret || filterWeekDay(*filter.Weekday, t)
	}
	return ret
}

func filterDate(c dateCondition, t time.Time) bool {
	if c.After != nil && t.After(*c.After) {
		return c.Before != nil && t.Before(*c.Before)
	}

	return c.Before != nil && t.Before(*c.Before)
}

func filterTime(c timeCondition, t time.Time) bool {
	if c.Before != 0 {
		if t.Hour() < c.Before {
			if c.After != 0 {
				return t.Hour() > c.After
			}
			return true
		}
	}

	return c.After != 0 && t.Hour() > c.After
}

func filterWeekDay(w time.Weekday, t time.Time) bool {
	return t.Weekday() == w
}

// DateFilter is used to filter events based on dates/times.
type DateFilter struct {
	Date    *dateCondition
	Time    *timeCondition
	Weekday *time.Weekday
}

// dateCondition can be built using a static time range but can also be
// computed automatically by using an "around" argument.
type dateCondition struct {
	Before *time.Time
	After  *time.Time
}

// timeCondition is used to select events based on the hours
type timeCondition struct {
	Before int
	After  int
}

type Reader struct {
	csv *csv.Reader
}

func NewReader(r io.Reader) *Reader {
	csvReader := csv.NewReader(r)
	csvReader.Comma = '|'
	return &Reader{csv: csvReader}
}

func fieldsToEntry(fields []string) (*Entry, error) {
	if len(fields) != 11 {
		return nil, fmt.Errorf("Invalid bodyfile format, expected 11 fields, got %d", len(fields))
	}

	e := Entry{}
	e.MD5 = fields[0]
	e.Name = fields[1]
	i, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("Inode was not an integer: %s", err)
	}

	e.Inode = int(i)
	e.Mode = fields[3]

	i, err = strconv.ParseInt(fields[4], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("UID was not an integer: %s", err)
	}
	e.UID = int(i)

	i, err = strconv.ParseInt(fields[5], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("GID was not an integer: %s", err)
	}
	e.GID = int(i)

	i, err = strconv.ParseInt(fields[6], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("Size was not an integer: %s", err)
	}
	e.Size = int(i)

	i, err = strconv.ParseInt(fields[7], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("AccessTime was not an integer: %s", err)
	}
	e.AccessTime = time.Unix(i, 0)

	i, err = strconv.ParseInt(fields[8], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("ModificationTime was not an integer: %s", err)
	}
	e.ModificationTime = time.Unix(i, 0)

	i, err = strconv.ParseInt(fields[9], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("ChangeTime was not an integer: %s", err)
	}
	e.ChangeTime = time.Unix(i, 0)

	i, err = strconv.ParseInt(fields[10], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("CreationTime was not an integer: %s", err)
	}
	e.CreationTime = time.Unix(i, 0)

	return &e, nil
}

func (b *Reader) Read() (*Entry, error) {
	fields, err := b.csv.Read()

	if err != nil {
		return nil, err
	}

	entry, err := fieldsToEntry(fields)
	if err != nil {
		return nil, err
	}

	return entry, nil
}

func ParseBodyLine(line string) (*Entry, error) {
	buf := bytes.NewBufferString(line)
	body := NewReader(buf)
	return body.Read()
}

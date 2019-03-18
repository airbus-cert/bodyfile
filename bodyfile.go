package bodyfile

import (
	"encoding/csv"
	"fmt"
	"io"
	"sort"
	"strconv"
	"time"

	"github.com/Knetic/govaluate"
)

// Entry represents one line of the bodyfile
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

	MatchingTimestamp int
}

// Reader is the reading object
type Reader struct {
	csv        *csv.Reader
	expression *govaluate.EvaluableExpression
	offset     int
	entries    tsEntrySortable
	Strict     bool
}

// NewReader instantiates a Reader object
func NewReader(r io.Reader) *Reader {
	csvReader := csv.NewReader(r)
	csvReader.Comma = '|'
	csvReader.Comment = '#'

	return &Reader{
		csv:    csvReader,
		offset: -1,
	}
}

// NewStrictReader instantiates a new Reader object with the Strict mode enabled
func NewStrictReader(r io.Reader) *Reader {
	reader := NewReader(r)
	reader.Strict = true
	return reader
}

// AddFilter adds a date restriction to filter the bodyfile
func (r *Reader) AddFilter(filter string) (err error) {
	r.expression, err = govaluate.NewEvaluableExpression(filter)
	return err
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

func entry2params(t time.Time) govaluate.Parameters {
	params := govaluate.MapParameters{}

	params["hour"] = t.Hour()
	params["min"] = t.Minute()
	params["day"] = t.Day()
	params["date"] = t.Unix()
	params["weekday"] = t.Weekday().String()

	params["h"] = t.Hour()
	params["m"] = t.Minute()
	params["D"] = t.Day()
	params["d"] = t.Unix()
	params["w"] = t.Weekday().String()

	return params
}

// Match filters the events
func (r *Reader) Match(entry *Entry) (bool, error) {
	ret := false
	if r.expression == nil {
		// no filter, everything matches
		return true, nil
	}

	params := entry2params(entry.AccessTime)
	decision, err := r.expression.Eval(params)
	if err != nil {
		return false, fmt.Errorf("Could not evaluate expression: %s", err)
	}
	ret = ret || decision.(bool)

	// fmt.Printf("AccessTime: %+v paramas=%+v\n", decision.(bool), params)
	if decision.(bool) {
		entry.MatchingTimestamp |= AccessTime
	}

	params = entry2params(entry.ModificationTime)
	decision, err = r.expression.Eval(params)
	if err != nil {
		return false, fmt.Errorf("Could not evaluate expression: %s", err)
	}
	// fmt.Printf("ModificationTime: %+v params=%+v\n", decision.(bool), params)
	ret = ret || decision.(bool)

	if decision.(bool) {
		entry.MatchingTimestamp |= ModificationTime
	}

	params = entry2params(entry.CreationTime)
	decision, err = r.expression.Eval(params)
	if err != nil {
		return false, fmt.Errorf("Could not evaluate expression: %s", err)
	}
	// fmt.Printf("CreationTime: %+v params=%+v\n", decision.(bool), params)
	ret = ret || decision.(bool)

	if decision.(bool) {
		entry.MatchingTimestamp |= CreationTime
	}

	params = entry2params(entry.ChangeTime)
	decision, err = r.expression.Eval(params)
	if err != nil {
		return false, fmt.Errorf("Could not evaluate expression: %s", err)
	}
	// fmt.Printf("ChangeTime: %+v params=%+v\n", decision.(bool), params)
	ret = ret || decision.(bool)
	if decision.(bool) {
		entry.MatchingTimestamp |= ChangeTime
	}

	return ret, nil
}

// These constants are used as a bitmap in Entry.MatchingTimestamps, it is useful to know
// which timestamp matched the filter.
const (
	AccessTime = 1 << iota
	ModificationTime
	ChangeTime
	CreationTime
)

// TimeStampedEntry is a wrapper around Entry to add an outer timestamp used for the
// sorted array
type TimeStampedEntry struct {
	Time  time.Time
	Entry *Entry
}

// tsEntrySortable is an interface to be used for sort.Sort()
type tsEntrySortable []TimeStampedEntry

func (e tsEntrySortable) Len() int {
	return len(e)
}

func (e tsEntrySortable) Swap(i int, j int) {
	e[i], e[j] = e[j], e[i]
}

func (e tsEntrySortable) Less(i int, j int) bool {
	return !e[i].Time.After(e[j].Time)
}

// Slurp reads all the content of the file in memory, filter out the non-matching events
func (r *Reader) Slurp() (int, error) {
	for {
		e, err := r.Read()
		if err == io.EOF {
			break
		}

		if err != nil {
			return 0, fmt.Errorf("Error while reading file: %s", err)
		}

		if !r.Strict || (r.Strict && ((AccessTime & e.MatchingTimestamp) != 0)) {
			r.entries = append(r.entries, TimeStampedEntry{e.AccessTime, e})
		}

		if e.ModificationTime != e.AccessTime {
			if !r.Strict || (r.Strict && ((ModificationTime & e.MatchingTimestamp) != 0)) {

				r.entries = append(r.entries, TimeStampedEntry{e.ModificationTime, e})
			}
		}
		if e.ChangeTime != e.ModificationTime && e.ChangeTime != e.AccessTime {
			if !r.Strict || (r.Strict && ((ChangeTime & e.MatchingTimestamp) != 0)) {

				r.entries = append(r.entries, TimeStampedEntry{e.ChangeTime, e})
			}
		}
		if e.CreationTime != e.ModificationTime && e.CreationTime != e.ChangeTime && e.CreationTime != e.AccessTime {
			if !r.Strict || (r.Strict && ((CreationTime & e.MatchingTimestamp) != 0)) {
				r.entries = append(r.entries, TimeStampedEntry{e.CreationTime, e})
			}
		}
	}

	sort.Sort(r.entries)

	r.offset = 0
	return len(r.entries), nil
}

// Next returns the next sorted elements
func (r *Reader) Next() (*TimeStampedEntry, error) {
	if r.offset < 0 {
		return nil, fmt.Errorf("Not initialized, call Slurp() first")
	}

	if r.offset >= len(r.entries) {
		return nil, io.EOF
	}

	r.offset++
	return &r.entries[r.offset-1], nil
}

// Read consumes CSV objects, instantiates them to Entry objects and applies filter
func (r *Reader) Read() (*Entry, error) {
	var entry *Entry
	matched := false

	for !matched {
		fields, err := r.csv.Read()

		if err != nil {
			return nil, err
		}

		entry, err = fieldsToEntry(fields)
		if err != nil {
			return nil, err
		}

		matched, err = r.Match(entry)
		if err != nil {
			return nil, err
		}
	}

	return entry, nil
}
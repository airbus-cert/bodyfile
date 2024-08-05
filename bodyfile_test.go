package bodyfile

import (
	"bytes"
	"io"
	"reflect"
	"testing"
	"time"
)

func Test_BodyfileWithALeadingEscapedPipes(t *testing.T) {
	input := `0|file\|with\|pipes\\|0|0|0|0|9529053861562548261|1331893980|1331893980|1331894001|1264526371`
	r := NewReader(bytes.NewBufferString(input))
	_, err := r.Read()
	if err != nil {
		t.Errorf("Could not read: %s", err)
	}
}
func Test_BodyfileWithPipes(t *testing.T) {
	input := `0|file\|with\|pipes|0|0|0|0|9529053861562548261|1331893980|1331893980|1331894001|1264526371`
	r := NewReader(bytes.NewBufferString(input))
	_, err := r.Read()
	if err != nil {
		t.Errorf("Could not read: %s", err)
	}
}

func Test_BodyfileUnquotedField(t *testing.T) {
	input := `0|Cissesrv        ImagePath="C:\Program Files\HP\Cissesrv\cissesrv.exe"|0||0|0|0|0|1535229693|0|0`
	r := NewReader(bytes.NewBufferString(input))
	_, err := r.Read()
	if err != nil {
		t.Errorf("Could not read: %s", err)
	}
}

func Test_BuggySize(t *testing.T) {
	input := `0|\\\WINDOWS\Debug\UserMode\ChkAcc.bak (indx)|0|0|0|0|9529053861562548261|1331893980|1331893980|1331894001|1264526371`
	r := NewReader(bytes.NewBufferString(input))
	_, err := r.Read()
	if err != nil {
		t.Errorf("Could not read: %s", err)
	}
}

func Test_InodeIsNotANumber(t *testing.T) {
	input := `0|c:/$MFT|0-128-12|r/rrwxrwxrwx|0|0|196870144|1689087082|1689087082|1689087082|1689087082`
	r := NewReader(bytes.NewBufferString(input))
	_, err := r.Read()
	if err != nil {
		t.Errorf("Could not read: %s", err)
	}
}

func Test_BodyfileParsing(t *testing.T) {
	// 2009-07-13T23:29:31Z    74240 .a.b 0 454      0        36434    \.\Windows\System32\oobe\audit.exe
	// 2009-07-14T01:38:55Z    74240 m... 0 454      0        36434    \.\Windows\System32\oobe\audit.exe
	// 2013-04-10T07:36:03Z    74240 ..c. 0 454      0        36434    \.\Windows\System32\oobe\audit.exe
	input := `0|\.\Windows\System32\oobe\audit.exe|36434|0|454|0|74240|1247527771|1247535535|1365579363|1247527771`
	acTime, _ := time.Parse(time.RFC3339, "2009-07-13T23:29:31Z")
	mTime, _ := time.Parse(time.RFC3339, "2009-07-14T01:38:55Z")
	cTime, _ := time.Parse(time.RFC3339, "2013-04-10T07:36:03Z")
	expected := Entry{
		MD5:              "0",
		Name:             `\.\Windows\System32\oobe\audit.exe`,
		Inode:            "36434",
		Mode:             "0",
		UID:              454,
		GID:              0,
		Size:             74240,
		AccessTime:       acTime,
		CreationTime:     acTime,
		ModificationTime: mTime,
		ChangeTime:       cTime,
	}
	r := NewReader(bytes.NewBufferString(input))
	entry, err := r.Read()
	if err != nil {
		t.Errorf("Could not read: %s", err)
	}

	if !reflect.DeepEqual(entry, &expected) {
		t.Errorf("expected %+v\n, got %+v", expected, entry)
	}
}

type FilterCase struct {
	Filter   string
	Expected bool
}

type TimeFilteringTestCase struct {
	Body    string
	Filters []FilterCase
}

func Test_FilterDate(t *testing.T) {
	testcases := []TimeFilteringTestCase{
		{
			Body: `0|\.\$MFT|0|0|256|0|284950528|1365579077|1365579077|1365579077|1365579077`,
			Filters: []FilterCase{
				{Expected: false, Filter: "date > '2018-11-10'"},
			},
		},
		{
			// 2009-07-13T01:29:31Z    74240 .a.b 0 454      0        36434    \.\Windows\System32\oobe\audit.exe
			// 2009-07-14T01:38:55Z    74240 m... 0 454      0        36434    \.\Windows\System32\oobe\audit.exe
			// 2013-04-10T07:36:03Z    74240 ..c. 0 454      0        36434    \.\Windows\System32\oobe\audit.exe
			Body: `0|\.\Windows\System32\oobe\audit.exe|36434|0|454|0|74240|1247527771|1247535535|1365579363|1247527771`,
			Filters: []FilterCase{
				{Expected: true, Filter: "date > '2013-04-09' && date < '2013-04-11'"},
				{Expected: true, Filter: "hour < 3 && hour > 0"},
				{Expected: true, Filter: "hour < 8"},
				{Expected: true, Filter: "hour > 6"},
			},
		},
		{
			// 2013-04-10T08:55:58Z 116773704 .a.b 0 497      0        64535    \.\Windows\System32\MRT.exe
			// 2015-02-16T14:40:50Z 116773704 m.c. 0 497      0        64535    \.\Windows\System32\MRT.exe
			Body: `0|\.\Windows\System32\MRT.exe|64535|0|497|0|116773704|1365584158|1424097650|1424097650|1365584158`,
			Filters: []FilterCase{
				{Expected: true, Filter: "hour <= 15 && hour >= 14"},
				{Expected: true, Filter: "weekday == 'Monday'"},
			},
		},
	}

	for _, tc := range testcases {
		for _, filter := range tc.Filters {
			r := NewReader(bytes.NewBufferString(tc.Body))
			r.AddFilter(filter.Filter)
			entry, err := r.Read()

			if err == io.EOF {
				if filter.Expected {
					t.Errorf("Filter(%v) did not matched even if it was supposed to", filter.Filter)
				}
				continue
			}

			if err != nil {
				t.Errorf("Could not read: %s", err)
				continue
			}

			if got := entry.MatchingTimestamp != 0; got != filter.Expected {
				t.Errorf("Filter(%v) returned %t while expecting %t", filter.Filter, got, filter.Expected)
			}
		}
	}

}

func Test_MinusOneTimestamp(t *testing.T) {
	input := `0|\\Users\John\Desktop\My Document.docx|291779||0|0|143711|-1|-1|-1|1427897741`

	r := NewReader(bytes.NewBufferString(input))
	n, err := r.Slurp()
	if err != nil {
		t.Errorf("Could not slurp: %s", err)
		return
	}

	if n > 1 {
		t.Errorf("Wrong number of results: expected 1, got %d", n)
		return
	}

	entry, err := r.Next()
	if err != nil {
		t.Errorf("Could not get the entry: %s", err)
		return
	}

	birthTime := entry.Entry.CreationTime
	if !entry.Time.Equal(birthTime) {
		t.Errorf("The only entry we get should have its Time equal to the Creation time: expected %+v, got %+v", birthTime, entry.Time)
		return
	}
}

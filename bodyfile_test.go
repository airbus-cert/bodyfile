package bodyfile

import (
	"bytes"
	"io"
	"reflect"
	"testing"
	"time"
)

func Test_BodyfileUnquotedField(t *testing.T) {
	input := `0|Cissesrv        ImagePath="C:\Program Files\HP\Cissesrv\cissesrv.exe"|0||0|0|0|0|1535229693|0|0`
	r := NewReader(bytes.NewBufferString(input))
	_, err := r.Read()
	if err != nil {
		t.Errorf("Could not read: %s", err)
	}
}

func Test_BodyfileParsing(t *testing.T) {
	input := `0|\.\Windows\System32\oobe\audit.exe|36434|0|454|0|74240|1247527771|1247535535|1365579363|1247527771`
	expected := Entry{
		MD5:              "0",
		Name:             `\.\Windows\System32\oobe\audit.exe`,
		Inode:            36434,
		Mode:             "0",
		UID:              454,
		GID:              0,
		Size:             74240,
		AccessTime:       time.Unix(1247527771, 0),
		ModificationTime: time.Unix(1247535535, 0),
		ChangeTime:       time.Unix(1365579363, 0),
		CreationTime:     time.Unix(1247527771, 0),
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

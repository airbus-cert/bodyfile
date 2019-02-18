package bodyfile

import (
	"reflect"
	"testing"
	"time"
)

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
	entry, err := ParseBodyLine(input)
	if err != nil {
		t.Errorf("ParseBodyLine() failed: %s", err)
	}

	if !reflect.DeepEqual(entry, &expected) {
		t.Errorf("expected %+v\n, got %+v", expected, entry)
	}
}

type FilterCase struct {
	Filter   DateFilter
	Expected bool
}

type TimeFilteringTestCase struct {
	Body    string
	Filters []FilterCase
}

func _date(s string) *time.Time {
	t, err := time.Parse(time.RFC3339, s+"T15:04:05Z")
	if err != nil {
		panic(err)
	}
	return &t
}

func p(i int) *int {
	return &i
}

func Test_FilterDate(t *testing.T) {
	w := time.Monday
	testcases := []TimeFilteringTestCase{
		{
			Body: `0|\.\$MFT|0|0|256|0|284950528|1365579077|1365579077|1365579077|1365579077`,
			Filters: []FilterCase{
				{Expected: false, Filter: DateFilter{Date: &dateCondition{After: _date("2018-11-10")}}},
			},
		},
		{
			// 2009-07-13T01:29:31Z    74240 .a.b 0 454      0        36434    \.\Windows\System32\oobe\audit.exe
			// 2009-07-14T01:38:55Z    74240 m... 0 454      0        36434    \.\Windows\System32\oobe\audit.exe
			// 2013-04-10T07:36:03Z    74240 ..c. 0 454      0        36434    \.\Windows\System32\oobe\audit.exe
			Body: `0|\.\Windows\System32\oobe\audit.exe|36434|0|454|0|74240|1247527771|1247535535|1365579363|1247527771`,
			Filters: []FilterCase{
				{Expected: true, Filter: DateFilter{Date: &dateCondition{After: _date("2013-04-09"), Before: _date("2013-04-11")}}},
				{Expected: true, Filter: DateFilter{Time: &timeCondition{Before: p(3), After: p(0)}}},
				{Expected: true, Filter: DateFilter{Time: &timeCondition{Before: p(8)}}},
				{Expected: true, Filter: DateFilter{Time: &timeCondition{After: p(6)}}},
			},
		},
		{
			// 2013-04-10T08:55:58Z 116773704 .a.b 0 497      0        64535    \.\Windows\System32\MRT.exe
			// 2015-02-16T14:40:50Z 116773704 m.c. 0 497      0        64535    \.\Windows\System32\MRT.exe
			Body: `0|\.\Windows\System32\MRT.exe|64535|0|497|0|116773704|1365584158|1424097650|1424097650|1365584158`,
			Filters: []FilterCase{
				//{Expected: true, Filter: DateFilter{Date: dateCondition{After: _date("2013-04-10"), After: _date("2013-04-11")}}},
				{Expected: true, Filter: DateFilter{Time: &timeCondition{Before: p(15), After: p(14)}}},
				{Expected: true, Filter: DateFilter{Weekday: &w}},
			},
		},
	}

	for _, tc := range testcases {
		entry, err := ParseBodyLine(tc.Body)
		if err != nil {
			t.Errorf("Could not parse line: %s", err)
		}

		for _, filter := range tc.Filters {
			if got := entry.TimeFilter(filter.Filter); got != filter.Expected {
				t.Errorf("FilterTime(%v) returned %t while expecting %t", filter.Filter, got, filter.Expected)
			}
		}
	}

}

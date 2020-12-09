package main

/*
EVTX monitoring utility, it can be used to make statistics on event generation
and to dump events in real time to files.

Copyright (C) 2017  RawSec SARL (0xrawsec)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/args"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-win32/win32/wevtapi"
)

const (
	// ExitSuccess RC
	ExitSuccess = 0
	// ExitFailure RC
	ExitFailure = 1
	Copyright   = "Evtmon Copyright (C) 2017 RawSec SARL (@0xrawsec)"
	License     = `License GPLv3: This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it under certain
conditions;`
)

type DurationArg time.Duration

func (da *DurationArg) String() string {
	return time.Duration(*da).String()
}

func (da *DurationArg) Set(input string) error {
	tda, err := time.ParseDuration(input)
	if err == nil {
		*da = DurationArg(tda)
	}
	return err
}

type Int64Slice []int64

func (is Int64Slice) Len() int {
	return len(is)
}

func (is Int64Slice) Swap(i, j int) {
	is[i], is[j] = is[j], is[i]
}
func (is Int64Slice) Less(i, j int) bool {
	return is[i] < is[j]
}

func FormatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

type ChannelStats struct {
	EventIDStats map[int64]uint
	EventIDs     Int64Slice
}

func NewChannelStats() *ChannelStats {
	cs := ChannelStats{}
	cs.EventIDStats = make(map[int64]uint)
	cs.EventIDs = make(Int64Slice, 0, 1024)
	return &cs
}

func (cs *ChannelStats) Update(e *evtx.GoEvtxMap) {
	if _, ok := cs.EventIDStats[e.EventID()]; !ok {
		cs.EventIDs = append(cs.EventIDs, e.EventID())
	}
	cs.EventIDStats[e.EventID()]++

}

func (cs *ChannelStats) Summary(start, stop time.Time) {
	sort.Sort(cs.EventIDs)
	for _, eid := range cs.EventIDs {
		fmt.Printf("\t\t%d: %d (%.2f eps)\n", eid, cs.EventIDStats[eid], float64(cs.EventIDStats[eid])/stop.Sub(start).Seconds())
	}
}

type Stats struct {
	sync.RWMutex
	Start         time.Time
	Stop          time.Time
	TimeLastEvent time.Time
	Filters       datastructs.SyncedSet
	EventCount    uint
	ChannelsStats map[string]*ChannelStats
}

func NewStats(filters ...int) (s Stats) {
	s.ChannelsStats = make(map[string]*ChannelStats)
	s.Filters = datastructs.NewSyncedSet()
	for _, f := range filters {
		s.Filters.Add(int64(f))
	}
	return
}

func (s *Stats) InitStart() {
	s.Start = time.Now()
}

func (s *Stats) Update(e *evtx.GoEvtxMap) {
	s.Lock()
	defer s.Unlock()
	// We take only those not filtered
	if !s.Filters.Contains(e.EventID()) {
		channel := e.Channel()
		if _, ok := s.ChannelsStats[channel]; !ok {
			s.ChannelsStats[channel] = NewChannelStats()
		}
		cs := s.ChannelsStats[channel]
		cs.Update(e)

		s.TimeLastEvent = e.TimeCreated()
		s.EventCount++
	}
}

func (s *Stats) DisplayStats() {
	s.RLock()
	defer s.RUnlock()
	fmt.Fprintf(os.Stderr, "Start: %s ", FormatTime(s.Start))
	fmt.Fprintf(os.Stderr, "TimeLastEvent: %s ", FormatTime(s.TimeLastEvent))
	fmt.Fprintf(os.Stderr, "EventCount: %d ", s.EventCount)
	eps := float64(s.EventCount) / time.Now().Sub(s.Start).Seconds()
	fmt.Fprintf(os.Stderr, "EPS: %.2f e/s\r", eps)
}

func (s *Stats) Summary() {
	s.RLock()
	defer s.RUnlock()
	s.Stop = time.Now()
	fmt.Printf("\n\n###### Summary #######\n\n")
	fmt.Printf("Start: %s\n", FormatTime(s.Start))
	fmt.Printf("Stop: %s\n", FormatTime(s.Stop))
	fmt.Printf("TimeLastEvent: %s\n", FormatTime(s.TimeLastEvent))
	fmt.Printf("Duration (stop - start): %s\n", s.Stop.Sub(s.Start))
	fmt.Printf("EventCount: %d\n", s.EventCount)
	eps := float64(s.EventCount) / s.Stop.Sub(s.Start).Seconds()
	fmt.Printf("Average EPS: %.2f eps\n", eps)
	fmt.Printf("EventIDs:\n")
	for channel, chanStats := range s.ChannelsStats {
		fmt.Printf("\t%s:\n", channel)
		chanStats.Summary(s.Start, s.Stop)
	}
}

func XMLEventToGoEvtxMap(xe *wevtapi.XMLEvent) (*evtx.GoEvtxMap, error) {
	ge := make(evtx.GoEvtxMap)
	bytes, err := json.Marshal(xe.ToJSONEvent())
	if err != nil {
		return &ge, err
	}
	err = json.Unmarshal(bytes, &ge)
	if err != nil {
		return &ge, err
	}
	return &ge, nil
}

var (
	// uninitialized
	statsFlag   bool
	debug       bool
	listAliases bool
	filters     args.ListIntVar
	duration    DurationArg
	output      string
	stats       Stats

	err    error
	ofile  *os.File
	writer *gzip.Writer

	// initialized
	eventProvider  = wevtapi.NewPullEventProvider()
	channelAliases = map[string]string{
		"sysmon":   "Microsoft-Windows-Sysmon/Operational",
		"security": "Security",
		"ps":       "Microsoft-Windows-PowerShell/Operational",
		"defender": "Microsoft-Windows-Windows Defender/Operational",
	}
	channels = make([]string, 0)
)

func terminate() {
	// No error handling
	if writer != nil {
		writer.Flush()
		writer.Close()
	}
	if ofile != nil {
		ofile.Close()
	}
	if statsFlag {
		stats.Summary()
	}
	os.Exit(ExitFailure)
}

func main() {

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s\n%s\nCommit: %s\n\n", Copyright, License, commitID)
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] CHANNELS|ALIASES...\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}

	flag.Var(&duration, "t", "Timeout for the test")
	flag.StringVar(&output, "w", output, "Write monitored events to output file")
	flag.BoolVar(&statsFlag, "s", statsFlag, "Outputs stats about events processed")
	flag.BoolVar(&listAliases, "l", listAliases, "List available channel aliases")
	flag.BoolVar(&debug, "d", debug, "Enable debug messages")

	flag.Parse()

	// set debug mode
	if debug {
		log.InitLogger(log.LDebug)
	}

	if listAliases {
		fmt.Printf("Channel aliases:\n")
		for a, c := range channelAliases {
			fmt.Printf("\t%s -> %s\n", a, c)
		}
		os.Exit(ExitSuccess)
	}

	stats = NewStats(filters...)
	wg := sync.WaitGroup{}

	// Signal handler to catch interrupt
	c := make(chan os.Signal, 1)
	ctx, cancel := context.WithCancel(context.Background())
	signal.Notify(c, os.Interrupt, os.Kill)
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-c
		eventProvider.Stop()
		cancel()
		terminate()
	}()

	if output != "" {
		ofile, err = os.Create(output)
		if err != nil {
			panic(err)
		}
		writer = gzip.NewWriter(ofile)

		defer writer.Flush()
		defer writer.Close()
		defer ofile.Close()
	}

	if statsFlag {
		go func() {
			for {
				if ctx.Err() == nil {
					time.Sleep(500 * time.Millisecond)
					stats.DisplayStats()
				}
			}
		}()
	}

	if duration > 0 {
		go func() {
			start := time.Now()
			for time.Now().Sub(start) < time.Duration(duration) {
				time.Sleep(time.Millisecond * 500)
			}
			cancel()
			terminate()
		}()
	}

	stats.InitStart()

	for _, channel := range flag.Args() {
		if alias, ok := channelAliases[channel]; ok {
			channels = append(channels, alias)
		} else {
			channels = append(channels, channel)
		}
	}

	if len(channels) > 0 {
		xmlEvents := eventProvider.FetchEvents(channels, wevtapi.EvtSubscribeToFutureEvents)
		for xe := range xmlEvents {
			e, err := XMLEventToGoEvtxMap(xe)
			if err != nil {
				log.Errorf("Failed to convert event: %s", err)
				log.Debugf("Error data: %v", xe)
			}
			if output != "" {
				writer.Write(evtx.ToJSON(e))
				writer.Write([]byte("\n"))
				writer.Flush()
			}
			if statsFlag {
				stats.Update(e)
			}
		}
	} else {
		log.LogErrorAndExit(fmt.Errorf("No channel to monitor"))
	}
	wg.Wait()
}

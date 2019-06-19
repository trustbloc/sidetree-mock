/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bddtests

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/godog"
)

var composition *Composition

func TestMain(m *testing.M) {

	// default is to run all tests with tag @all
	tags := "all"
	flag.Parse()
	cmdTags := flag.CommandLine.Lookup("test.run")
	if cmdTags != nil && cmdTags.Value != nil && cmdTags.Value.String() != "" {
		tags = cmdTags.Value.String()
	}

	initBDDConfig()

	status := godog.RunWithOptions("godogs", func(s *godog.Suite) {
		s.BeforeSuite(func() {

			if os.Getenv("DISABLE_COMPOSITION") != "true" {

				// Need a unique name, but docker does not allow '-' in names
				composeProjectName := strings.Replace(generateUUID(), "-", "", -1)
				newComposition, err := NewComposition(composeProjectName, "docker-compose.yml", "./fixtures")
				if err != nil {
					panic(fmt.Sprintf("Error composing system in BDD context: %s", err))
				}

				composition = newComposition

				fmt.Println("docker-compose up ... waiting for peer to start ...")
				testSleep := 5
				if os.Getenv("TEST_SLEEP") != "" {
					testSleep, _ = strconv.Atoi(os.Getenv("TEST_SLEEP"))
				}
				fmt.Printf("*** testSleep=%d", testSleep)
				time.Sleep(time.Second * time.Duration(testSleep))
			}

		})

		s.AfterSuite(func() {
			if composition != nil {
				composition.GenerateLogs("./fixtures")
				composition.Decompose("./fixtures")
			}
		})

		FeatureContext(s)
	}, godog.Options{
		Tags:          tags,
		Format:        "progress",
		Paths:         []string{"features"},
		Randomize:     time.Now().UTC().UnixNano(), // randomize scenario execution order
		Strict:        true,
		StopOnFailure: true,
	})

	if st := m.Run(); st > status {
		status = st
	}
	os.Exit(status)
}

func FeatureContext(s *godog.Suite) {

	context, err := NewBDDContext()
	if err != nil {
		panic(fmt.Sprintf("Error returned from NewBDDContext: %s", err))
	}

	// Context is shared between tests - for now
	// Note: Each test after NewcommonSteps. should add unique steps only
	NewDIDSideSteps(context).RegisterSteps(s)
}

func initBDDConfig() {
}

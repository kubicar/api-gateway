package ratelimit

import (
	"github.com/cucumber/godog"
)

func initScenario(ctx *godog.ScenarioContext, ts *testsuite) {
	scenario := ts.createScenario()

	ctx.Step(`^Calling the "([^"]*)" endpoint with "([^"]*)" method (\d+) times should result in status code (\d+) for requests$`, scenario.callingTheEndpointWithMethodTimesShouldResultInStatusCodeForRequests)
	ctx.Step(`^RateLimit with default bucket empty is applied$`, scenario.rateLimitWithDefaultBucketEmptyIsApplied)
	ctx.Step(`^There is a httpbin service$`, scenario.thereIsAHttpbinService)
}

Feature: Rate limiting

  Scenario: Rate limit connectivity to pod for default bucket empty
    Given There is a httpbin service
    When RateLimit with default bucket empty is applied
    Then Calling the "/ip" endpoint with "GET" method 10 times should result in status code 429 for requests

# demo-service

The sample repository used by `just demo`. A one-function service with a
failing test (`greet()` ignores its argument), a test runner
(`./run_tests.sh`), and a stand-in release script (`./deploy.sh`) that the
demo policy deliberately gates behind human approval.

The demo copies this directory into `.demo/repo` and runs the agent against a
fluidbox-managed copy of *that* — this checkout is never modified by a run.

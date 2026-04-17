package handlers

// OPAQUE test helper functions were removed (dead code).
// All 4 functions (setupOPAQUEMocks, expectOPAQUERegistration, expectOPAQUEAuthentication,
// validateOPAQUEHealthy) had zero references outside this file.
//
// The OPAQUE handlers call auth package functions directly via CGO (no interface).
// To unit-test OPAQUE handlers, an OPAQUEOperations interface would need to be
// introduced in the auth package first. See docs/wip/archive/fix-go-unit-tests2.md
// "Deferred: OPAQUE Handler Unit Tests" section for details.

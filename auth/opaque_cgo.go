package auth

/*
#cgo CFLAGS: -I../vendor/aldenml/ecc/include
#cgo LDFLAGS: -L../vendor/aldenml/ecc/build -lecc
#include "opaque_wrapper.h"
*/
import "C"

// This file will contain the CGo wrapper functions that call the C functions from the aldenml/ecc library.

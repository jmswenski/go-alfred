package alfred

/*
#include "binding.h"
*/
import "C"

func setTestSocket(fd int) {
	C.go_alfred_test_set_socket(C.int(fd))
}

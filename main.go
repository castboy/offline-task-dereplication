package main

import (
	"net/http"
	"off-line-dispatch/controllers"
)

func main() {
    http.HandleFunc("/dereplication", controllers.Dereplication)
    http.ListenAndServe(":8091", nil)
}


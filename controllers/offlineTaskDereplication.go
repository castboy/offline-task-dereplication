/*离线任务去重*/
package controllers

import (
	"fmt"
	"net/http"
	//"net/url"
    "io"
	"off-line-dispatch/models"

	//"github.com/julienschmidt/httprouter"
)

func Dereplication(w http.ResponseWriter, r *http.Request) {

    r.ParseForm()
    para := r.Form["para"][0]
	if para == "" {
		fmt.Println("the para is null")
	} else {
        fmt.Println(para)
	}

	res := models.Dereplication(para)

	io.WriteString(w, res)
}


package plg_editor_eml

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/gonejack/email"
	"github.com/gorilla/mux"
	. "github.com/mickael-kerjean/filestash/server/common"
	"github.com/mickael-kerjean/filestash/server/ctrl"
	. "github.com/mickael-kerjean/filestash/server/middleware"
	"github.com/mickael-kerjean/filestash/server/model"
	"io"
	"mime"
	"net/http"
	"strings"
)

func init() {
	if plugin_enable := Config.Get("features.emlviewer.enable").Schema(func(f *FormElement) *FormElement {
		if f == nil {
			f = &FormElement{}
		}
		f.Default = true
		f.Name = "enable"
		f.Type = "boolean"
		f.Target = []string{}
		f.Description = "Enable/Disable eml viewer. This setting requires a restart to come into effect."
		f.Placeholder = "Default: true"
		return f
	}).Bool(); plugin_enable == false {
		return
	}

	Hooks.Register.HttpEndpoint(func(r *mux.Router, app *App) error {
		r.HandleFunc(
			COOKIE_PATH+"emlviewer/iframe",
			NewMiddlewareChain(
				ContentHandler,
				[]Middleware{SessionStart, LoggedInOnly},
				*app,
			),
		).Methods("GET")
		return nil
	})
	Hooks.Register.XDGOpen(`
    if(mime === "message/rfc822") {
              return ["appframe", {"endpoint": "/api/emlviewer/iframe"}];
       }
    `)
}

func ContentHandler(ctx App, res http.ResponseWriter, req *http.Request) {
	if model.CanRead(&ctx) == false {
		SendErrorResult(res, ErrPermissionDenied)
		return
	}
	query := req.URL.Query()
	path, err := ctrl.PathBuilder(ctx, query.Get("path"))
	if err != nil {
		SendErrorResult(res, err)
		return
	}

	f, err := ctx.Backend.Cat(path)
	if err != nil {
		SendErrorResult(res, err)
		return
	}

	html, err := convertEml(path, f)
	if err != nil {
		SendErrorResult(res, err)
		return
	}

	res.Write([]byte(fmt.Sprintf(html)))
}

func convertEml(path string, eml io.Reader) (string, error) {
	var emlBuf bytes.Buffer
	tee := io.TeeReader(eml, &emlBuf)

	mail, err := email.NewEmailFromReader(tee)
	if err != nil {
		return "", fmt.Errorf("cannot parse email: %s", err)
	}

	emailContent := "<div>"
	if len(mail.Subject) > 0 {
		title := mail.Subject
		decoded, err := decodeRFC2047(title)
		if err == nil {
			title = decoded
		}
		emailContent += fmt.Sprintf(
			`<span title="subject" style="font-size: x-large;" class="eml-header-item"><b>%s</b></span><br>`,
			title)
	}
	if len(mail.Headers.Get("Date")) > 0 {
		emailContent += fmt.Sprintf(
			`<span class="eml-header-item">Sent: %s</span><br>`,
			mail.Headers.Get("Date"))
	}
	if len(mail.From) > 0 {
		emailContent += fmt.Sprintf(
			`<span class="eml-header-item">From: %s</span><br>`,
			mail.From)
	}
	if len(mail.To) > 0 {
		emailContent += fmt.Sprintf(
			`<span class="eml-header-item">To: %s</span><br>`,
			mail.To)
	}
	if len(mail.Cc) > 0 {
		emailContent += fmt.Sprintf(
			`<span class="eml-header-item">Cc: %s</span><br>`,
			mail.Cc)
	}
	if len(mail.Bcc) > 0 {
		emailContent += fmt.Sprintf(
			`<span class="eml-header-item">Bcc: %s</span><br>`,
			mail.Bcc)
	}
	emailContent += `</div><hr style="height:1px;border-width:0;color:gray;background-color:gray" />`
	if len(mail.HTML) > 0 {
		emailContent += fmt.Sprintf(
			`<div class="eml-content"><p>%s</p></div>`,
			mail.HTML)
	}
	if len(mail.Text) > 0 {
		if len(mail.HTML) > 0 {
			emailContent += fmt.Sprintf(
				`<button type="button" class="eml-collapsible">Text Body</button><div class="hidden-eml-content"><p><pre>%s</pre></p></div>`,
				mail.Text)
		} else {
			emailContent += fmt.Sprintf(
				`<div class="eml-content"><p><pre>%s</pre></p></div>`,
				mail.Text)
		}
	}
	emailContent += `<hr style="height:1px;border-width:0;color:gray;background-color:gray" />`
	if len(mail.HTMLHeaders) > 0 {
		emailContent += fmt.Sprintf(
			`<button type="button" class="eml-collapsible">HTML Headers</button><div class="hidden-eml-content"><p>%s</p></div>`,
			mail.HTMLHeaders)
	}
	if len(mail.Headers) > 0 {
		emailContent += fmt.Sprintf(
			`<button type="button" class="eml-collapsible">Headers</button><div class="hidden-eml-content"><p>%s</p></div>`,
			mail.Headers)
	}

	emailContent += fmt.Sprintf(
		`<button type="button" class="eml-collapsible">Raw Email</button><div class="hidden-eml-content"><p><pre>%s</pre></p></div>`,
		emlBuf.String())

	html := fmt.Sprintf(
		`
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
   <meta name="viewport" content="width=device-width, initial-scale=1">
<style>
.eml-header-item{
  padding:5px;
  position: relative;
  display: inline-block;
  width: 100%%;
  color: black;
}
.eml-header-item:nth-of-type(odd){
  background-color: #f1f1f1;
}
.eml-header-item:nth-of-type(even){
  background-color: white;
}
.eml-collapsible {
  background-color: #777;
  color: white;
  cursor: pointer;
  padding: 5px;
  width: 100%%;
  border: none;
  text-align: left;
  outline: none;
  font-size: 15px;
}
.active, .eml-collapsible:hover {
  background-color: #555;
}
.eml-content {
  padding: 0 18px;
  display: block;
  overflow: hidden;
  background-color: #f1f1f1;
}
.hidden-eml-content {
  padding: 0 18px;
  display: none;
  overflow: hidden;
  background-color: #f1f1f1;
}
</style>
</head>
  <body>
    <div id="editor" style="background: lightgray;">%s</div>
	<script>
	var coll = document.getElementsByClassName("eml-collapsible");
	var i;

	for (i = 0; i < coll.length; i++) {
	  coll[i].addEventListener("click", function() {
		this.classList.toggle("active");
		var content = this.nextElementSibling;
		if (content.style.display === "block") {
		  content.style.display = "nofiles/ne";
		} else {
		  content.style.display = "block";
		}
	  });
	}
	</script>
  </body>
</html>`, emailContent)

	return html, nil
}

func decodeRFC2047(word string) (string, error) {
	isRFC2047 := strings.HasPrefix(word, "=?") && strings.Contains(word, "?=")
	if isRFC2047 {
		isRFC2047 = strings.Contains(word, "?Q?") || strings.Contains(word, "?B?")
	}
	if !isRFC2047 {
		return word, nil
	}

	comps := strings.Split(word, "?")
	if len(comps) < 5 {
		return word, nil
	}

	if comps[2] == "B" && strings.HasSuffix(comps[3], "=") {
		b64s := strings.TrimRight(comps[3], "=")
		text, _ := base64.RawURLEncoding.DecodeString(b64s)
		comps[3] = base64.StdEncoding.EncodeToString(text)
	}

	return new(mime.WordDecoder).DecodeHeader(strings.Join(comps, "?"))
}

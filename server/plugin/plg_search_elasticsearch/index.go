package plg_search_elasticsearch

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	elasticsearch7 "github.com/elastic/go-elasticsearch/v7"
	. "github.com/mickael-kerjean/filestash/server/common"
	"net/http"
	"os"
	"strings"
)

const highlight_pre_tag = "<span id=\"search_result\" style=\"background-color: #FFFF00\">"
const highlight_post_tag = "</span>"

type ElasticSearch struct {
	Es7          *elasticsearch7.Client
	Index        string
	IndexPrefix  string
	IndexSuffix  string
	PathField    string
	ContentField string
	SizeField    string
	TimeField    string
	NumFragment  int
	MaxAnalyzedOffset int
	MaxAnalyzedOffsetSupported bool
	MaxResultSize int
}

func init() {
	if plugin_enable := Config.Get("features.elasticsearch.enable").Schema(func(f *FormElement) *FormElement {
		if f == nil {
			f = &FormElement{}
		}
		f.Default = false
		f.Name = "enable"
		f.Type = "boolean"
		f.Target = []string{}
		f.Description = "Enable/Disable search using ElasticSearch. Please note that indexing is not handled by this plugin. This setting requires a restart to come into effect."
		f.Placeholder = "Default: false"
		if u := os.Getenv("ELASTICSEARCH_URL"); u != "" {
			f.Default = true
		}
		return f
	}).Bool(); plugin_enable == false {
		return
	}
	Config.Get("features.elasticsearch.url").Schema(func(f *FormElement) *FormElement {
		if f == nil {
			f = &FormElement{}
		}
		f.Id = "url"
		f.Name = "url"
		f.Type = "text"
		f.Description = "Location of your ElasticSearch server(s)"
		f.Default = ""
		f.Placeholder = "Eg: http://127.0.0.1:9200[,http://127.0.0.1:9201]"
		if u := os.Getenv("ELASTICSEARCH_URL"); u != "" {
			f.Default = u
			f.Placeholder = fmt.Sprintf("Default: '%s'", u)
		}
		return f
	})
	Config.Get("features.elasticsearch.username").Schema(func(f *FormElement) *FormElement {
		if f == nil {
			f = &FormElement{}
		}
		f.Id = "username"
		f.Name = "username"
		f.Type = "text"
		f.Description = "Username for connecting to Elasticsearch"
		f.Default = ""
		f.Placeholder = "Eg: username"
		if u := os.Getenv("ELASTICSEARCH_USERNAME"); u != "" {
			f.Default = u
			f.Placeholder = fmt.Sprintf("Default: '%s'", u)
		}
		return f
	})
	Config.Get("features.elasticsearch.password").Schema(func(f *FormElement) *FormElement {
		if f == nil {
			f = &FormElement{}
		}
		f.Id = "password"
		f.Name = "password"
		f.Type = "password"
		f.Description = "Password for connecting to Elasticsearch"
		f.Default = ""
		f.Placeholder = "Eg: password"
		if u := os.Getenv("ELASTICSEARCH_PASSWORD"); u != "" {
			f.Default = u
			f.Placeholder = fmt.Sprintf("Default: '%s'", u)
		}
		return f
	})
	Config.Get("features.elasticsearch.index").Schema(func(f *FormElement) *FormElement {
		if f == nil {
			f = &FormElement{}
		}
		f.Id = "index"
		f.Name = "index"
		f.Type = "text"
		f.Description = "Name of the Elasticsearch index. If empty, top level folder (lower case) is assumed to be the index name."
		f.Default = ""
		f.Placeholder = "Eg: filestash_index"
		if u := os.Getenv("ELASTICSEARCH_INDEX"); u != "" {
			f.Default = u
			f.Placeholder = fmt.Sprintf("Default: '%s'", u)
		}
		return f
	})
	Config.Get("features.elasticsearch.index_prefix").Schema(func(f *FormElement) *FormElement {
		if f == nil {
			f = &FormElement{}
		}
		f.Id = "index_prefix"
		f.Name = "index_prefix"
		f.Type = "text"
		f.Description = "Prefix for Elasticsearch index."
		f.Default = ""
		f.Placeholder = "Eg: filestash_index_prefix"
		return f
	})
	Config.Get("features.elasticsearch.index_suffix").Schema(func(f *FormElement) *FormElement {
		if f == nil {
			f = &FormElement{}
		}
		f.Id = "index_suffix"
		f.Name = "index_suffix"
		f.Type = "text"
		f.Description = "Suffix for Elasticsearch index."
		f.Default = ""
		f.Placeholder = "Eg: filestash_index_suffix"
		return f
	})
	Config.Get("features.elasticsearch.field_path").Schema(func(f *FormElement) *FormElement {
		if f == nil {
			f = &FormElement{}
		}
		f.Id = "field_path"
		f.Name = "field_path"
		f.Type = "text"
		f.Description = "Field name for file path. Path must be keyword type to restrict search."
		f.Default = ""
		f.Placeholder = "Eg: path_field"
		if u := os.Getenv("ELASTICSEARCH_FIELD_PATH"); u != "" {
			f.Default = u
			f.Placeholder = fmt.Sprintf("Default: '%s'", u)
		}
		return f
	})
	Config.Get("features.elasticsearch.field_content").Schema(func(f *FormElement) *FormElement {
		if f == nil {
			f = &FormElement{}
		}
		f.Id = "field_content"
		f.Name = "field_content"
		f.Type = "text"
		f.Description = "Field name for file content"
		f.Default = ""
		f.Placeholder = "Eg: content_field"
		if u := os.Getenv("ELASTICSEARCH_FIELD_CONTENT"); u != "" {
			f.Default = u
			f.Placeholder = fmt.Sprintf("Default: '%s'", u)
		}
		return f
	})
	Config.Get("features.elasticsearch.field_size").Schema(func(f *FormElement) *FormElement {
		if f == nil {
			f = &FormElement{}
		}
		f.Id = "field_size"
		f.Name = "field_size"
		f.Type = "text"
		f.Description = "Field name for file size"
		f.Default = ""
		f.Placeholder = "Eg: size_field"
		if u := os.Getenv("ELASTICSEARCH_FIELD_SIZE"); u != "" {
			f.Default = u
			f.Placeholder = fmt.Sprintf("Default: '%s'", u)
		}
		return f
	})
	Config.Get("features.elasticsearch.field_time").Schema(func(f *FormElement) *FormElement {
		if f == nil {
			f = &FormElement{}
		}
		f.Id = "field_time"
		f.Name = "field_time"
		f.Type = "text"
		f.Description = "Field name for file time"
		f.Default = ""
		f.Placeholder = "Eg: time_field"
		if u := os.Getenv("ELASTICSEARCH_FIELD_TIME"); u != "" {
			f.Default = u
			f.Placeholder = fmt.Sprintf("Default: '%s'", u)
		}
		return f
	})
	Config.Get("features.elasticsearch.num_fragment").Schema(func(f *FormElement) *FormElement {
		if f == nil {
			f = &FormElement{}
		}
		f.Id = "num_fragment"
		f.Name = "num_fragment"
		f.Type = "number"
		f.Description = "Max number of snippets in file to display. 0 will return whole file with results highlighted"
		f.Default = 5
		f.Placeholder = "Eg: 5"
		return f
	})
	Config.Get("features.elasticsearch.max_analyzed_offset").Schema(func(f *FormElement) *FormElement {
		if f == nil {
			f = &FormElement{}
		}
		f.Id = "max_analyzed_offset"
		f.Name = "max_analyzed_offset"
		f.Type = "number"
		f.Description = "Maximum number of characters in search result that will be analyzed for highlight. Supported in ES version >= 7.12)"
		f.Default = 1000000
		f.Placeholder = "Eg: 1000000"
		return f
	})
	Config.Get("features.elasticsearch.max_result_size").Schema(func(f *FormElement) *FormElement {
		if f == nil {
			f = &FormElement{}
		}
		f.Id = "max_result_size"
		f.Name = "max_result_size"
		f.Type = "number"
		f.Description = "Max number of search results. (Max value based on index.max_result_window, defaults to 10000)"
		f.Default = 1000
		f.Placeholder = "Eg: 1000"
		return f
	})
	Config.Get("features.elasticsearch.enable_display_result_title").Schema(func(f *FormElement) *FormElement {
		if f == nil {
			f = &FormElement{}
		}
		f.Id = "enable_display_result_title"
		f.Name = "enable_display_result_title"
		f.Type = "boolean"
		f.Description = "Enable displaying of first 200 characters from snippet as title"
		f.Default = true
		return f
	})
	Config.Get("features.elasticsearch.enable_root_search").Schema(func(f *FormElement) *FormElement {
		if f == nil {
			f = &FormElement{}
		}
		f.Id = "enable_root_search"
		f.Name = "enable_root_search"
		f.Type = "boolean"
		f.Description = "Enable searching from root level"
		f.Default = false
		return f
	})
	Config.Get("features.elasticsearch.enable_self_signed").Schema(func(f *FormElement) *FormElement {
		if f == nil {
			f = &FormElement{}
		}
		f.Default = true
		f.Name = "enable_self_signed"
		f.Type = "boolean"
		f.Target = []string{}
		f.Description = "Enable/Disable self signed cert on ES cluster."
		f.Placeholder = "Default: true"
		if u := os.Getenv("ELASTICSEARCH_ENABLE_SELF_SIGNED"); u != "" {
			f.Default = true
		}
		return f
	})

	cfg := elasticsearch7.Config{
		Addresses: strings.Split(Config.Get("features.elasticsearch.url").String(), ","),
	}
	if Config.Get("features.elasticsearch.username").String() != "" {
		cfg.Username = Config.Get("features.elasticsearch.username").String()
	}
	if Config.Get("features.elasticsearch.password").String() != "" {
		cfg.Password = Config.Get("features.elasticsearch.password").String()
	}

	//https://stackoverflow.com/questions/37557763
	if Config.Get("features.elasticsearch.enable_self_signed").Bool() {
		transport := http.DefaultTransport
		tlsClientConfig := &tls.Config{InsecureSkipVerify: true}
		transport.(*http.Transport).TLSClientConfig = tlsClientConfig
		cfg.Transport = transport
	}

	var (
		r map[string]interface{}
	)

	es7, err := elasticsearch7.NewClient(cfg)
	if err != nil {
		Log.Error("ES::init Error creating elasticsearch client: %s", err)
		return
	}
	res, err := es7.Info()
	if err != nil {
		Log.Error("ES::init Error getting response: %s", err)
		return
	}
	defer res.Body.Close()
	// Check response status
	if res.IsError() {
		Log.Error("ES::init Error: %s", res.String())
		return
	}
	// Deserialize the response into a map.
	if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
		Log.Error("ES::init Error parsing the response body: %s", err)
		return
	}
	// Print client and server version numbers.
	Log.Debug("ES::init Client: %s", elasticsearch7.Version)
	Log.Debug("ES::init Server: %s", r["version"].(map[string]interface{})["number"])
	Log.Debug(strings.Repeat("~", 37))

	// check es version to detect if MaxAnalyzedOffset is supported
	major, minor, patch, _ := elasticsearch7.ParseElasticsearchVersion(r["version"].(map[string]interface{})["number"].(string))
	maxAnalyzedOffsetSupported := false
	if  major > 7 || (major == 7 && minor >= 12) {
		maxAnalyzedOffsetSupported = true
	}

	es := &ElasticSearch{
		Es7:          					es7,
		Index:        					Config.Get("features.elasticsearch.index").String(),
		IndexPrefix:  					Config.Get("features.elasticsearch.index_prefix").String(),
		IndexSuffix:  					Config.Get("features.elasticsearch.index_suffix").String(),
		PathField:    					Config.Get("features.elasticsearch.field_path").String(),
		ContentField: 					Config.Get("features.elasticsearch.field_content").String(),
		SizeField:    					Config.Get("features.elasticsearch.field_size").String(),
		TimeField:    					Config.Get("features.elasticsearch.field_time").String(),
		NumFragment:  					Config.Get("features.elasticsearch.num_fragment").Int(),
		MaxAnalyzedOffset: 				Config.Get("features.elasticsearch.max_analyzed_offset").Int(),
		MaxAnalyzedOffsetSupported:		maxAnalyzedOffsetSupported,
		MaxResultSize: Config.Get("features.elasticsearch.max_result_size").Int(),
	}

	Hooks.Register.SearchEngine(es)
}

func (this ElasticSearch) Query(app App, path string, keyword string) ([]IFile, error) {
	Log.Debug("ES::Query path: %s, keyword, %s", path, keyword)
	if path == "/" {
		if Config.Get("features.elasticsearch.enable_root_search").Bool() {
			path = "*"
		} else {
			return nil, NewError("Cannot search from root level.", 404)
		}
	}
	var (
		r map[string]interface{}
	)

	// check path valid and user has list permission
	pathChildren, err := app.Backend.Ls(path)
	if err != nil {
		Log.Error("ES::query Error accessing search path: %s", err)
		return nil, err
	}

	indexes := []string{}
	if len(strings.TrimSpace(this.Index)) > 0 {
		indexes = append(indexes, this.IndexPrefix+this.Index+this.IndexSuffix)
	} else if path == "*" {
		for i := range pathChildren {
			if pathChildren[i].IsDir() {
				indexes = append(indexes, this.IndexPrefix+pathChildren[i].Name()+this.IndexSuffix)
			}
		}
		Log.Debug("ES::query root search indexes: %s", strings.Join(indexes, ","))
	}

	// Build the request body.
	// Path must be keyword type to restrict search. Otherwise, search may be global.
	var buf bytes.Buffer
	query := map[string]interface{}{
		"size": this.MaxResultSize,
		"query": map[string]interface{}{
			"query_string": map[string]interface{}{
				"fields": [2]string{this.ContentField, this.PathField},
				"query":  "(" + this.PathField + ":" + strings.ReplaceAll(path, "/", "\\/") + "*) AND (" + keyword + ")",
			},
		},
		"_source": false,
		"fields":  [3]string{this.PathField, this.SizeField, this.TimeField},
		"highlight": map[string]interface{}{
			//"max_analyzed_offset": this.MaxAnalyzedOffset,
			"number_of_fragments": this.NumFragment,
			"pre_tags":            [1]string{highlight_pre_tag},
			"post_tags":           [1]string{highlight_post_tag},
			"fields": map[string]interface{}{
				this.ContentField: map[string]interface{}{},
			},
		},
	}
	if this.MaxAnalyzedOffsetSupported {
		query["highlight"].(map[string]interface{})["max_analyzed_offset"] = this.MaxAnalyzedOffset
	}

	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		Log.Error("ES::Query query_builder: Error encoding query: %s", err)
		return nil, ErrNotFound
	}

	if len(indexes) == 0 {
		// extract index from path (bucket level index)
		indexes = append(indexes, this.IndexPrefix+strings.ToLower(strings.Split(path, "/")[1])+this.IndexSuffix)
	}

	// Perform the search request.
	res, err := this.Es7.Search(
		this.Es7.Search.WithContext(context.Background()),
		this.Es7.Search.WithIndex(indexes...),
		this.Es7.Search.WithBody(&buf),
		this.Es7.Search.WithTrackTotalHits(true),
		this.Es7.Search.WithPretty(),
	)

	if err != nil {
		Log.Error("ES::Query search: Error getting response: %s", err)
		res.Body.Close()
		return nil, ErrNotFound
	}
	defer res.Body.Close()

	if res.IsError() {
		var e map[string]interface{}
		if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
			Log.Error("ES::Query search: Error parsing the response body: %s", err)
			res.Body.Close()
			return nil, ErrNotFound
		} else {
			// Print the response status and error information.
			Log.Debug("ES::Query search: [%s] %v",
				res.Status(),
				e["error"],
			)
			return nil, NewError(e["error"].(map[string]interface{})["reason"].(string), 404)
		}
	}

	if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
		Log.Error("ES::Query search: Error parsing the response body: %s", err)
		res.Body.Close()
		return nil, ErrNotFound
	}
	// Print the response status, number of results, and request duration.
	Log.Debug(
		"ES::Query search: [%s] %d hits; took: %dms",
		res.Status(),
		int(r["hits"].(map[string]interface{})["total"].(map[string]interface{})["value"].(float64)),
		int(r["took"].(float64)),
	)

	files := []IFile{}

	// Print the ID and document source for each hit.
	for _, hit := range r["hits"].(map[string]interface{})["hits"].([]interface{}) {

		resPath := hit.(map[string]interface{})["fields"].(map[string]interface{})[this.PathField].([]interface{})[0].(string)
		size := int64(hit.(map[string]interface{})["fields"].(map[string]interface{})[this.SizeField].([]interface{})[0].(float64))
		time := int64(hit.(map[string]interface{})["fields"].(map[string]interface{})[this.TimeField].([]interface{})[0].(float64) * 1000) // FTime in msecs

		pathTokens := strings.Split(resPath, "/")
		resFilename := pathTokens[len(pathTokens)-1]

		snippet := ""
		if highlights := hit.(map[string]interface{})["highlight"]; highlights != nil {
			if contentHighlights := highlights.(map[string]interface{})[this.ContentField]; contentHighlights != nil {
				snippet = "<hr style=\"height:1px;border-width:0;color:gray;background-color:gray\" />"
				for _, contentHighlight := range contentHighlights.([]interface{}) {
					snippet = snippet + contentHighlight.(string) + "<hr style=\"height:1px;border-width:0;color:gray;background-color:gray\" />"
				}
			}
		}

		hits := int64(strings.Count(snippet, highlight_pre_tag))
		if len(snippet) == 0 {
			snippet = resPath
			hits = 1
		}

		files = append(files, File{
			FName:    resFilename,
			FType:    "file", // ENUM("file", "directory")
			FSize:    size,
			FTime:    time,
			FPath:    resPath,
			FSnippet: snippet,
			FHits:    hits,
		})
	}
	Log.Debug(strings.Repeat("=", 37))

	return files, nil
}

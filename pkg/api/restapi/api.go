package restapi

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/rtemka/caesarcypher"
)

const (
	encodeMode         = "encode"
	decodeMode         = "decode"
	bruteForceMethod   = "brute-force"
	freqAnalisysMethod = "freq"
	keyParam           = "key"
	modeParam          = "mode"
	methodParam        = "method"
)

// API represents service REST programming interface
type API struct {
	r   *mux.Router
	log *log.Logger
}

func New(logger *log.Logger) *API {
	api := &API{
		r:   mux.NewRouter(),
		log: logger,
	}
	api.endpoints()

	return api
}

// Router returns *API router to use in *http.Server
// as mux
func (api *API) Router() *mux.Router {
	return api.r
}

func (api *API) endpoints() {
	api.r.Use(api.closerMiddleware, api.logRequestMiddleware, api.headersMiddleware)
	api.r.HandleFunc("/cyphers/{name}", api.caesarHandler).Methods(http.MethodPost, http.MethodOptions)
}

// closerMiddleware drains and closes request body
func (api *API) closerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
	})
}

// headersMiddleware sets uniform headers to all responses
func (api *API) headersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// logRequestMiddleware logs request params
func (api *API) logRequestMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.log.Printf("method=%s, path=%s, query=%s host=%s", r.Method, r.URL.Path, r.URL.Query(), r.Host)
		next.ServeHTTP(w, r)
	})
}

// caesarHandler reads request query parameters
//  and routes request to appropriate handler
func (api *API) caesarHandler(w http.ResponseWriter, r *http.Request) {

	if v, ok := mux.Vars(r)["name"]; !ok || v != "caesar" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	mode := r.URL.Query().Get(modeParam)
	switch mode {
	case encodeMode:
		api.encryptionHandler(w, r)
	case decodeMode:
		api.decryptionHandler(w, r)
	case "":

		http.Error(w, fmt.Sprintf("not found '%s' query parameter", modeParam), http.StatusBadRequest)
		return
	default:
		http.Error(w, "unsupported mode", http.StatusNotImplemented)
		return
	}
}

func (api *API) encryptionHandler(w http.ResponseWriter, r *http.Request) {
	k, err := strconv.Atoi(r.URL.Query().Get(keyParam))
	if err != nil {
		http.Error(w, "invalid key", http.StatusBadRequest)
		return
	}
	c, err := caesarcypher.NewCypher(k, api.log)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	c.NewEncrypter(w).Encrypt(r.Body)
}

func (api *API) decryptionHandler(w http.ResponseWriter, r *http.Request) {

	v := r.URL.Query()

	switch v.Get(methodParam) {

	case bruteForceMethod:
		api.bruteForceHandler(w, r)

	case freqAnalisysMethod:
		api.freqAnalisysHandler(w, r)

	case "":
		if v.Get(keyParam) == "" {
			http.Error(w, fmt.Sprintf("not found '%s' query parameter", methodParam), http.StatusBadRequest)
			return
		}
		api.keyHandler(w, r)
	default:
		http.Error(w, "unsupported decryption method", http.StatusNotImplemented)
	}
}

func (api *API) bruteForceHandler(w http.ResponseWriter, r *http.Request) {
	c, err := caesarcypher.NewCypher(0, api.log)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	c.NewDecrypter(r.Body).BruteForce().Decrypt(w)
}

func (api *API) freqAnalisysHandler(w http.ResponseWriter, r *http.Request) {
	c, err := caesarcypher.NewCypher(0, api.log)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	c.NewDecrypter(r.Body).FrequencyAnalysis().Decrypt(w)
}

func (api *API) keyHandler(w http.ResponseWriter, r *http.Request) {
	k, err := strconv.Atoi(r.URL.Query().Get(keyParam))
	if err != nil {
		http.Error(w, "invalid key", http.StatusBadRequest)
		return
	}
	c, err := caesarcypher.NewCypher(k, api.log)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	c.NewDecrypter(r.Body).Decrypt(w)
}

package restapi

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	decrypted = "В самом начале своего жизнеописания я должен упомянуть о том, что родился я в пятницу, в полночь. " +
		"Замечено было, что мой первый крик раздался, когда начали бить часы. Принимая во внимание день и час моего появления" +
		" на свет, сиделка и несколько мудрых соседок, живо интересовавшихся моей особой еще за много месяцев до возможного " +
		"личного знакомства со мной, объявили, что мне суждено быть несчастным в жизни."
	encrypted = `ОЛюмщыщЛъм-мшсЛюоыспыЛухфъсыьхюмъхГЛГЛрышусъЛ:ьыщГъ:яАЛыЛяыщЕЛ-яыЛэырхшюГЛГЛоЛьГяъх?:ЕЛоЛьышъы-АЙЛФмщс-съыЛн ` +
		`шыЕЛ-яыЛщыцЛьсэо цЛчэхчЛэмфрмшюГЕЛчыпрмЛъм-мшхЛнхяАЛ-мю ЙЛЬэхъхщмГЛоыЛоъхщмъхсЛрсъАЛхЛ-мюЛщыспыЛьыГошсъхГЛъмЛюосяЕЛюхрсшчмЛх` +
		`ЛъсючышАчыЛщ:рэ "ЛюыюсрычЕЛухоыЛхъясэсюыомо—х"юГЛщысцЛыюыныцЛс.сЛфмЛщъыпыЛщсюГ?соЛрыЛоыфщыуъыпыЛшх-ъыпыЛфъмчыщюяомЛюыЛщъыцЕЛын!` +
		`ГохшхЕЛ-яыЛщъсЛю:урсъыЛн яАЛъсю-мюяъ щЛоЛухфъхЙ`
	testKey = 13
)

func TestAPI(t *testing.T) {
	api := New(log.New(io.Discard, "", 0))
	ts := httptest.NewServer(api.Router())
	defer ts.Close()

	assert := assert.New(t)

	t.Run("bad_request", func(t *testing.T) {

		url1 := fmt.Sprintf("%s/cyphers/vigener?mode=%s&key=%d", ts.URL, encodeMode, testKey)
		url2 := fmt.Sprintf("%s/cyphers/caesar?mode=%s&key=%d", ts.URL, "", testKey)
		url3 := fmt.Sprintf("%s/cyphers/caesar?mode=%s&key=%d", ts.URL, "super-decode", testKey)

		res, err := http.Post(url1, "text/plain", nil)
		if err != nil {
			t.Fatalf("API.caesarHandler() error = %v", err)
		}

		assert.Equal(http.StatusNotFound, res.StatusCode, "API.caesarHandler()")
		res.Body.Close()

		res, err = http.Post(url2, "text/plain", nil)
		if err != nil {
			t.Fatalf("API.caesarHandler() error = %v", err)
		}

		assert.Equal(http.StatusBadRequest, res.StatusCode, "API.caesarHandler()")

		b, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("API.caesarHandler() error = %v", err)
		}

		assert.Equal("not found 'mode' query parameter\n", string(b), "API.caesarHandler()")
		res.Body.Close()

		res, err = http.Post(url3, "text/plain", nil)
		if err != nil {
			t.Fatalf("API.caesarHandler() error = %v", err)
		}

		assert.Equal(http.StatusNotImplemented, res.StatusCode, "API.caesarHandler()")

		b, err = io.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("API.caesarHandler() error = %v", err)
		}

		assert.Equal("unsupported mode\n", string(b), "API.caesarHandler()")
		res.Body.Close()

	})

	t.Run("encode", func(t *testing.T) {

		want := encrypted
		url := fmt.Sprintf("%s/cyphers/caesar?mode=%s&key=%d", ts.URL, encodeMode, testKey)

		res, err := http.Post(url, "text/plain", strings.NewReader(decrypted))
		if err != nil {
			t.Fatalf("API.encryptionHandler() error = %v", err)
		}
		defer res.Body.Close()

		assert.Equal(http.StatusOK, res.StatusCode, "API.encryptionHandler()")

		b, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("API.encryptionHandler() error = %v", err)
		}

		assert.Equal(want, string(b), "API.encryptionHandler()")
	})

	t.Run("decode", func(t *testing.T) {

		want := decrypted
		url := fmt.Sprintf("%s/cyphers/caesar?mode=%s&key=%d", ts.URL, decodeMode, testKey)

		res, err := http.Post(url, "text/plain", strings.NewReader(encrypted))
		if err != nil {
			t.Fatalf("API.decryptionHandler() error = %v", err)
		}
		defer res.Body.Close()

		assert.Equal(http.StatusOK, res.StatusCode, "API.decryptionHandler()")

		b, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("API.decryptionHandler() error = %v", err)
		}

		assert.Equal(want, string(b), "API.decryptionHandler()")
	})

	t.Run("decode_brute_force", func(t *testing.T) {

		want := decrypted
		url := fmt.Sprintf("%s/cyphers/caesar?mode=%s&method=%s", ts.URL, decodeMode, bruteForceMethod)

		res, err := http.Post(url, "text/plain", strings.NewReader(encrypted))
		if err != nil {
			t.Fatalf("API.decryptionHandler() error = %v", err)
		}
		defer res.Body.Close()

		assert.Equal(http.StatusOK, res.StatusCode, "API.bruteForceHandler()")

		b, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("API.bruteForceHandler() error = %v", err)
		}

		assert.Equal(want, string(b), "API.bruteForceHandler()")
	})

	t.Run("decode_freq_analisys", func(t *testing.T) {

		want := decrypted
		url := fmt.Sprintf("%s/cyphers/caesar?mode=%s&method=%s", ts.URL, decodeMode, freqAnalisysMethod)

		res, err := http.Post(url, "text/plain", strings.NewReader(encrypted))
		if err != nil {
			t.Fatalf("API.decryptionHandler() error = %v", err)
		}
		defer res.Body.Close()

		assert.Equal(http.StatusOK, res.StatusCode, "API.freqAnalisysHandler()")

		b, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("API.freqAnalisysHandler() error = %v", err)
		}

		assert.Equal(want, string(b), "API.freqAnalisysHandler()")
	})
}

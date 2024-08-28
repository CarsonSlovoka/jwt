package jwt

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"time"
)

// KeyFunc 回傳值 key 為 ISigningMethod.Verify 所用到的key，因此可以根據token的類型去回傳特定的鑰匙
// 另外你也可以回傳 []key 的型態 請參考 parser.validate
type KeyFunc func(*Token) (key any, err error)

var TimePrecision = time.Second

// MarshalSingleStringAsArray 如果數值只是一個字串，就會把它變放進到slice裡面，即 "my-str" => ["my-str"]
var MarshalSingleStringAsArray = true

// NumericDate represents a JSON numeric date value, as referenced at
// https://datatracker.ietf.org/doc/html/rfc7519#section-2.
// 主要就是時間，但我們希望可以依據 jwt.TimePrecision 來變化爬取的規則
type NumericDate struct {
	time.Time
}

func NewNumericDate(t time.Time) *NumericDate {
	return &NumericDate{t.Truncate(TimePrecision)}
}

func newNumericDateFromSeconds(f float64) *NumericDate {
	round, frac := math.Modf(f)
	return NewNumericDate(time.Unix(int64(round), int64(frac*1e9)))
}

func (date NumericDate) MarshalJSON() (b []byte, err error) {
	var precise int
	if TimePrecision < time.Second {
		precise = int(math.Log10(float64(time.Second) / float64(TimePrecision)))
	}
	truncatedDate := date.Truncate(TimePrecision)
	seconds := strconv.FormatInt(truncatedDate.Unix(), 10)
	nanosecondsOffset := strconv.FormatFloat(float64(truncatedDate.Nanosecond())/float64(time.Second), 'f', precise, 64)
	output := append([]byte(seconds), []byte(nanosecondsOffset)[1:]...)
	return output, nil
}

func (date *NumericDate) UnmarshalJSON(b []byte) (err error) {
	var (
		number json.Number
		f      float64
	)
	if err = json.Unmarshal(b, &number); err != nil {
		return fmt.Errorf("could not parse NumericData: %w", err)
	}
	if f, err = number.Float64(); err != nil {
		return fmt.Errorf("could not convert json number value to float: %w", err)
	}
	n := newNumericDateFromSeconds(f)
	*date = *n
	return nil
}

// ClaimStrings 自定義了json.Unmarshal, json.MarshalJSON 為了
// input => output
// string => [string]  (需要透過 jwt.MarshalSingleStringAsArray 設定(預設啟用))
// []any => []string
type ClaimStrings []string

func (s *ClaimStrings) UnmarshalJSON(data []byte) (err error) {
	var value any

	if err = json.Unmarshal(data, &value); err != nil {
		return err
	}

	var aud []string
	switch v := value.(type) {
	case string:
		aud = append(aud, v)
	case []string:
		aud = v
	case []any:
		for _, vv := range v {
			vs, ok := vv.(string)
			if !ok {
				return ErrInvalidType
			}
			aud = append(aud, vs)
		}
	case nil:
		return nil
	default:
		return ErrInvalidType
	}
	*s = aud
	return
}

func (s ClaimStrings) MarshalJSON() (b []byte, err error) {
	if len(s) == 1 && !MarshalSingleStringAsArray {
		return json.Marshal(s[0])
	}
	// return json.Marshal(s) // 這個又會調用自己
	return json.Marshal([]string(s)) // 轉換成[]string // https://go.dev/play/p/eRhO-nnKTSE
}

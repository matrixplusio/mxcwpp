package model

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- JSONValue / JSONScan 测试 ---

func TestJSONValue_Struct(t *testing.T) {
	type sample struct {
		Name string `json:"name"`
	}
	val, err := JSONValue(sample{Name: "test"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"name":"test"}`, string(val.([]byte)))
}

func TestJSONValue_Slice(t *testing.T) {
	val, err := JSONValue([]string{"a", "b"})
	require.NoError(t, err)
	assert.JSONEq(t, `["a","b"]`, string(val.([]byte)))
}

func TestJSONValue_Nil(t *testing.T) {
	val, err := JSONValue(nil)
	require.NoError(t, err)
	assert.Equal(t, []byte("null"), val.([]byte))
}

func TestJSONScan_NilValue(t *testing.T) {
	var dest []string
	err := JSONScan(&dest, nil)
	require.NoError(t, err)
	assert.Nil(t, dest)
}

func TestJSONScan_NonBytes(t *testing.T) {
	var dest []string
	err := JSONScan(&dest, 12345)
	require.NoError(t, err)
	assert.Nil(t, dest) // 非 []byte 类型直接返回 nil
}

func TestJSONScan_ValidBytes(t *testing.T) {
	var dest []string
	err := JSONScan(&dest, []byte(`["x","y"]`))
	require.NoError(t, err)
	assert.Equal(t, []string{"x", "y"}, dest)
}

func TestJSONScan_InvalidJSON(t *testing.T) {
	var dest map[string]string
	err := JSONScan(&dest, []byte(`{invalid}`))
	assert.Error(t, err)
}

// --- LocalTime JSON 序列化测试 ---

func TestLocalTime_MarshalJSON(t *testing.T) {
	tt := time.Date(2026, 5, 7, 12, 30, 0, 0, time.UTC)
	lt := LocalTime(tt)

	data, err := json.Marshal(lt)
	require.NoError(t, err)
	assert.Equal(t, `"2026-05-07 12:30:00"`, string(data))
}

func TestLocalTime_MarshalJSON_Zero(t *testing.T) {
	var lt LocalTime
	data, err := json.Marshal(lt)
	require.NoError(t, err)
	assert.Equal(t, "null", string(data))
}

func TestLocalTime_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  time.Time
	}{
		{
			name:  "标准格式",
			input: `"2026-05-07 12:30:00"`,
			want:  time.Date(2026, 5, 7, 12, 30, 0, 0, time.UTC),
		},
		{
			name:  "RFC3339 格式",
			input: `"2026-05-07T12:30:00Z"`,
			want:  time.Date(2026, 5, 7, 12, 30, 0, 0, time.UTC),
		},
		{
			name:  "ISO8601 无时区",
			input: `"2026-05-07T12:30:00"`,
			want:  time.Date(2026, 5, 7, 12, 30, 0, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var lt LocalTime
			err := json.Unmarshal([]byte(tt.input), &lt)
			require.NoError(t, err)
			assert.Equal(t, tt.want, time.Time(lt))
		})
	}
}

func TestLocalTime_UnmarshalJSON_Null(t *testing.T) {
	var lt LocalTime
	err := json.Unmarshal([]byte(`null`), &lt)
	require.NoError(t, err)
	assert.True(t, lt.IsZero())
}

func TestLocalTime_UnmarshalJSON_InvalidFormat(t *testing.T) {
	var lt LocalTime
	err := json.Unmarshal([]byte(`"not-a-date"`), &lt)
	assert.Error(t, err)
}

// --- LocalTime database Value/Scan 测试 ---

func TestLocalTime_Value_NonZero(t *testing.T) {
	tt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	lt := LocalTime(tt)
	val, err := lt.Value()
	require.NoError(t, err)
	assert.Equal(t, tt, val)
}

func TestLocalTime_Value_Zero(t *testing.T) {
	var lt LocalTime
	val, err := lt.Value()
	require.NoError(t, err)
	assert.Nil(t, val)
}

func TestLocalTime_Scan_TimeValue(t *testing.T) {
	tt := time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)
	var lt LocalTime
	err := lt.Scan(tt)
	require.NoError(t, err)
	assert.Equal(t, tt, time.Time(lt))
}

func TestLocalTime_Scan_ByteSlice(t *testing.T) {
	var lt LocalTime
	err := lt.Scan([]byte("2026-03-15 10:00:00"))
	require.NoError(t, err)
	assert.Equal(t, "2026-03-15 10:00:00", lt.String())
}

func TestLocalTime_Scan_String(t *testing.T) {
	var lt LocalTime
	err := lt.Scan("2026-03-15 10:00:00")
	require.NoError(t, err)
	assert.Equal(t, "2026-03-15 10:00:00", lt.String())
}

func TestLocalTime_Scan_Nil(t *testing.T) {
	var lt LocalTime
	err := lt.Scan(nil)
	require.NoError(t, err)
	assert.True(t, lt.IsZero())
}

func TestLocalTime_Scan_UnsupportedType(t *testing.T) {
	var lt LocalTime
	err := lt.Scan(12345)
	assert.Error(t, err)
}

// --- LocalTime 辅助方法测试 ---

func TestLocalTime_Methods(t *testing.T) {
	t1 := LocalTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	t2 := LocalTime(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))

	assert.True(t, t2.After(t1))
	assert.True(t, t1.Before(t2))
	assert.False(t, t1.After(t2))
	assert.False(t, t2.Before(t1))
	assert.False(t, t1.IsZero())
	assert.Equal(t, "2026-01-01 00:00:00", t1.String())
}

func TestNow(t *testing.T) {
	before := time.Now()
	lt := Now()
	after := time.Now()

	assert.False(t, time.Time(lt).Before(before))
	assert.False(t, time.Time(lt).After(after))
}

func TestToLocalTime(t *testing.T) {
	tt := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	lt := ToLocalTime(tt)
	assert.Equal(t, tt, lt.Time())
}

func TestToLocalTimePtr(t *testing.T) {
	tt := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	lt := ToLocalTimePtr(&tt)
	require.NotNil(t, lt)
	assert.Equal(t, tt, lt.Time())
}

func TestToLocalTimePtr_Nil(t *testing.T) {
	lt := ToLocalTimePtr(nil)
	assert.Nil(t, lt)
}

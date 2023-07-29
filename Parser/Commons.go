package main

import (
	"fmt"
	"reflect"
	"strconv"
)

const MAX_TAG_VAL_BYTES = 500

func ellipsis(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	if maxLen < 3 {
		maxLen = 3
	}
	return string(runes[0:maxLen-3]) + "..."
}

type TagPair struct{ k, v string }

func UnwrapObject(obj interface{}, key string) <-chan TagPair {
	chnl := make(chan TagPair)
	go func() {
		v := reflect.ValueOf(obj)
		for i := 0; i < v.NumField(); i++ {
			field := v.Type().Field(i)
			tag := field.Tag
			label := tag.Get(key)
			if tag == "" || label == "" {
				continue
			}
			value := fmt.Sprintf("%v", v.Field(i))
			if value == "" {
				continue
			}
			chnl <- TagPair{label, value}
		}
		close(chnl)
	}()
	return chnl
}

func hexStr2DecStr(hex string) string {
	n, err := strconv.ParseInt(hex, 16, 64)
	if err != nil {
		panic(err)
	}
	return strconv.FormatInt(n, 10)
}
